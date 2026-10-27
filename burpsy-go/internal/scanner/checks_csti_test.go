package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

// ---------------------------------------------------------------------------
// Simulated pages: the decision logic is tested against engines written here, so every guard has a
// fast, browser-free test and a negative control. The live twins below exercise the real browser.
// ---------------------------------------------------------------------------

// cstiSimPage renders a page for a URL: the DOM the browser would show, the served body, and the
// run-time requests the page issued.
type cstiSimPage func(u *url.URL, fragment, q string) (dom, served string, reqs []domexec.RenderedRequest)

type cstiSim struct {
	page    cstiSimPage
	calls   int
	served  int
	noServe bool
}

func (s *cstiSim) RenderedDOMWithOptions(_ context.Context, target string, _ domexec.RenderOptions) (string, domexec.RenderOutcome, error) {
	s.calls++
	u, frag, q := cstiSimParse(target)
	dom, _, reqs := s.page(u, frag, q)
	return dom, domexec.RenderOutcome{Requests: reqs}, nil
}

func (s *cstiSim) env() cstiEnv {
	return cstiEnv{
		render: s,
		served: func(_ context.Context, target string) (string, bool) {
			if s.noServe {
				return "", false
			}
			s.served++
			u, _, q := cstiSimParse(target)
			_, served, _ := s.page(u, "", q)
			return served, true
		},
		authorise: func(string) error { return nil },
	}
}

func cstiSimParse(target string) (*url.URL, string, string) {
	u, err := url.Parse(target)
	if err != nil {
		panic(err)
	}
	frag, _ := url.QueryUnescape(u.EscapedFragment())
	return u, frag, u.Query().Get("q")
}

var cstiSimArith = regexp.MustCompile(`\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}`)

// cstiSimEvaluate is a {{a*b}} engine.
func cstiSimEvaluate(s string) string {
	return cstiSimArith.ReplaceAllStringFunc(s, func(m string) string {
		p := cstiSimArith.FindStringSubmatch(m)
		a, _ := strconv.Atoi(p[1])
		b, _ := strconv.Atoi(p[2])
		return strconv.Itoa(a * b)
	})
}

const cstiSimTarget = "http://app.test:8080/p?q=shoes"

func runCSTISim(t *testing.T, page cstiSimPage, forms []cstiForm) (cstiOutcome, *cstiSim) {
	t.Helper()
	sim := &cstiSim{page: page}
	out, err := auditCSTI(context.Background(), sim.env(), cstiSimTarget, forms)
	if err != nil {
		t.Fatalf("audit error: %v", err)
	}
	return out, sim
}

// fragmentEngine: the fragment is template source evaluated in the browser.
func fragmentEngine(_ *url.URL, frag, q string) (string, string, []domexec.RenderedRequest) {
	served := "<p>" + q + "</p>"
	return served + "<div>" + cstiSimEvaluate(frag) + "</div>", served, nil
}

// reflectedEngine: q is reflected by the server and evaluated by the browser.
func reflectedEngine(_ *url.URL, _, q string) (string, string, []domexec.RenderedRequest) {
	served := "<div ng-app>" + q + "</div>"
	return "<div ng-app>" + cstiSimEvaluate(q) + "</div>", served, nil
}

func TestCSTIFindsAFragmentEvaluatedInTheBrowser(t *testing.T) {
	out, _ := runCSTISim(t, fragmentEngine, cstiForms())
	if out.proof == nil {
		t.Fatalf("no proof; undecided=%v", out.undecided)
	}
	if out.proof.source != "the URL fragment" || out.proof.servedConsulted {
		t.Errorf("proof names %q (served consulted %v), want the fragment", out.proof.source, out.proof.servedConsulted)
	}
	if out.proof.first.expected == out.proof.second.expected {
		t.Errorf("the confirmation reused the first challenge: %+v", out.proof)
	}
	for _, c := range []cstiChallenge{out.proof.first, out.proof.second} {
		if strings.Contains(c.payload, c.expected) || len(c.expected) < 9 {
			t.Errorf("challenge %+v: the value must be computed, at least nine digits, and absent from the payload", c)
		}
	}
}

func TestCSTIFindsServerReflectedInputEvaluatedInTheBrowser(t *testing.T) {
	out, sim := runCSTISim(t, reflectedEngine, cstiForms())
	if out.proof == nil || !strings.Contains(out.proof.source, `"q"`) || !out.proof.servedConsulted {
		t.Fatalf("want a proof through q with the served response consulted; got %+v undecided=%v", out.proof, out.undecided)
	}
	if sim.served == 0 {
		t.Fatal("the served response was never read, so server-side evaluation was not ruled out")
	}
}

// A server-side engine renders the same product; that is SSTI's finding, not this row's.
func TestCSTIStaysQuietWhenTheServerEvaluated(t *testing.T) {
	serverSide := func(_ *url.URL, _, q string) (string, string, []domexec.RenderedRequest) {
		page := "<div>" + cstiSimEvaluate(q) + "</div>"
		return page, page, nil
	}
	out, _ := runCSTISim(t, serverSide, cstiForms())
	if out.proof != nil {
		t.Fatalf("server-side evaluation was reported as client-side: %+v", out.proof)
	}
}

// Negative control for the served-response guard: without it the server-side page fires.
func TestCSTIServedResponseGuardIsWhatKeepsServerEvaluationOut(t *testing.T) {
	serverSide := func(_ *url.URL, _, q string) (string, string, []domexec.RenderedRequest) {
		return "<div>" + cstiSimEvaluate(q) + "</div>", "<div>" + q + "</div>", nil // guard blinded
	}
	if out, _ := runCSTISim(t, serverSide, cstiForms()); out.proof == nil {
		t.Fatal("with the served response blinded the page should have fired; the previous test then proves nothing")
	}
}

func TestCSTIIsUndecidedWhenTheServedResponseCannotBeRead(t *testing.T) {
	sim := &cstiSim{page: reflectedEngine, noServe: true}
	out, err := auditCSTI(context.Background(), sim.env(), cstiSimTarget, cstiForms())
	if err != nil {
		t.Fatal(err)
	}
	if out.proof != nil || len(out.undecided) == 0 {
		t.Fatalf("want undecided, got proof=%+v undecided=%v", out.proof, out.undecided)
	}
}

// numbersPage prints "42" and the digits of the input on their own, and strips the delimiters from
// its echoes so the expression never reappears verbatim: the page the constant 7*6 proof reported.
func numbersPage(_ *url.URL, frag, q string) (string, string, []domexec.RenderedRequest) {
	strip := strings.NewReplacer("{", "", "}", "", "[", "", "]", "", "$", "", "#", "", "^", "", "/", "")
	digits := regexp.MustCompile(`\D`).ReplaceAllString(q, "")
	served := "<p>Reference: " + digits + "</p><p>" + strip.Replace(q) + "</p>"
	dom := served
	if frag != "" {
		dom += "<p>42 results for " + strip.Replace(frag) + "</p>"
	}
	return dom, served, nil
}

func TestCSTIStaysQuietOnAPageThatPrintsNumbersOnItsOwn(t *testing.T) {
	out, _ := runCSTISim(t, numbersPage, cstiForms())
	if out.proof != nil || len(out.undecided) != 0 {
		t.Fatalf("a page printing 42 / the input's digits was not clean: proof=%+v undecided=%v", out.proof, out.undecided)
	}
}

// Negative control: the old constant 7*6 proof is fooled by the numbers page at the probe level,
// and only the fresh-challenge guards keep it out.
func TestCSTIConstantProofWouldReportTheNumbersPage(t *testing.T) {
	constant := cstiForm{family: "constant", render: func() cstiChallenge {
		return cstiChallenge{payload: "{{7*6}}", expected: "42", marker: "7*6"}
	}}
	sim := &cstiSim{page: numbersPage}
	var out cstiOutcome
	render := func(u string) (string, domexec.RenderOutcome, error) {
		return sim.RenderedDOMWithOptions(context.Background(), u, domexec.RenderOptions{})
	}
	baseline, _, _ := render(cstiSimTarget)
	srcs, _ := cstiSources(cstiSimTarget)
	if _, res := cstiProbe(context.Background(), sim.env(), &out, render, srcs[0], constant, baseline); res != cstiEvaluated {
		t.Fatalf("the constant 7*6 probe was not fooled by the numbers page (%v), so the fixture does not reproduce the defect", out.undecided)
	}
	if got, _ := runCSTISim(t, numbersPage, []cstiForm{constant}); got.proof != nil {
		t.Fatalf("a constant challenge confirmed itself: %+v", got.proof)
	}
}

// A first hit that does not reproduce is undecided, never a finding and never clean.
func TestCSTIRequiresTheSecondChallengeToReproduce(t *testing.T) {
	hits := 0
	once := func(u *url.URL, frag, q string) (string, string, []domexec.RenderedRequest) {
		if cstiSimArith.MatchString(frag) {
			hits++
			if hits > 1 {
				return "<div>no</div>", "", nil
			}
		}
		return fragmentEngine(u, frag, q)
	}
	out, _ := runCSTISim(t, once, cstiForms())
	if out.proof != nil {
		t.Fatalf("an unconfirmed hit was reported: %+v", out.proof)
	}
	if len(out.undecided) == 0 {
		t.Fatal("an unconfirmed hit was reported as clean")
	}
}

// Negative control: a form whose second render repeats the first payload is refused.
func TestCSTIRefusesAConfirmationThatIsNotIndependent(t *testing.T) {
	ch := NewArithmeticChallenge()
	fixed := []cstiForm{{family: "fixed", render: func() cstiChallenge {
		return cstiChallenge{payload: "{{" + ch.Expr() + "}}", expected: ch.Product(), marker: ch.Expr()}
	}}}
	out, _ := runCSTISim(t, fragmentEngine, fixed)
	if out.proof != nil || len(out.undecided) == 0 {
		t.Fatalf("a repeated challenge confirmed itself: proof=%+v undecided=%v", out.proof, out.undecided)
	}
}

func TestCSTIRefusesAValueTheBaselineOrPayloadAlreadyCarries(t *testing.T) {
	inPayload := []cstiForm{{family: "spelled", render: func() cstiChallenge {
		return cstiChallenge{payload: "{{1*123456789}}123456789", expected: "123456789", marker: "x"}
	}}}
	echo := func(_ *url.URL, frag, q string) (string, string, []domexec.RenderedRequest) {
		return "<div>" + frag + "</div>", "", nil
	}
	if out, _ := runCSTISim(t, echo, inPayload); out.proof != nil {
		t.Fatalf("a payload that spells its own value was believed: %+v", out.proof)
	}
	inBaseline := []cstiForm{{family: "baseline", render: func() cstiChallenge {
		return cstiChallenge{payload: "{{11111*11111}}", expected: "123454321", marker: "11111"}
	}}}
	always := func(u *url.URL, frag, q string) (string, string, []domexec.RenderedRequest) {
		return "<div>order 123454321</div><div>" + frag + "</div>", "", nil
	}
	if out, _ := runCSTISim(t, always, inBaseline); out.proof != nil || len(out.undecided) == 0 {
		t.Fatalf("a value already in the baseline was believed or reported clean: %+v", out)
	}
	// At the probe level, before the confirmation guard gets a say.
	sim := &cstiSim{page: always}
	var out cstiOutcome
	render := func(u string) (string, domexec.RenderOutcome, error) {
		return sim.RenderedDOMWithOptions(context.Background(), u, domexec.RenderOptions{})
	}
	baseline, _, _ := render(cstiSimTarget)
	srcs, _ := cstiSources(cstiSimTarget)
	if _, res := cstiProbe(context.Background(), sim.env(), &out, render, srcs[0], inBaseline[0], baseline); res != cstiUndecided {
		t.Fatalf("a probe whose value the baseline shows was classified %v, want undecided", res)
	}
}

// The bare form is only sent where the canary sat in an expression attribute, so a calculator that
// evaluates a*b typed into q is not template injection.
func TestCSTIBareExpressionOnlyInsideAnExpressionAttribute(t *testing.T) {
	bare := regexp.MustCompile(`^(\d+)\*(\d+)$`)
	calc := func(attr bool) cstiSimPage {
		return func(_ *url.URL, _, q string) (string, string, []domexec.RenderedRequest) {
			out := q
			if m := bare.FindStringSubmatch(q); m != nil {
				a, _ := strconv.Atoi(m[1])
				b, _ := strconv.Atoi(m[2])
				out = strconv.Itoa(a * b)
			}
			if attr {
				return `<span ng-bind="` + q + `">` + out + `</span>`, `<span ng-bind="` + q + `"></span>`, nil
			}
			return "<p>= " + out + "</p>", "<p></p>", nil
		}
	}
	if out, _ := runCSTISim(t, calc(false), cstiForms()); out.proof != nil {
		t.Fatalf("a calculator was reported as template injection: %+v", out.proof)
	}
	out, _ := runCSTISim(t, calc(true), cstiForms())
	if out.proof == nil || !strings.Contains(out.proof.family, "expression attribute") {
		t.Fatalf("the ng-bind reflection was missed: %+v undecided=%v", out.proof, out.undecided)
	}
}

func TestCSTIMustacheSectionProof(t *testing.T) {
	section := regexp.MustCompile(`\{\{#(\w+)\}\}(\w*)\{\{/(\w+)\}\}\{\{\^(\w+)\}\}(\w*)\{\{/(\w+)\}\}`)
	mustache := func(_ *url.URL, _, q string) (string, string, []domexec.RenderedRequest) {
		return "<div>" + section.ReplaceAllString(q, "$5") + "</div>", "<script type=x-template>" + q + "</script>", nil
	}
	out, _ := runCSTISim(t, mustache, cstiForms())
	if out.proof == nil || !strings.Contains(out.proof.family, "Mustache") {
		t.Fatalf("the Mustache section was not proved: %+v undecided=%v", out.proof, out.undecided)
	}
	stripTags := regexp.MustCompile(`\{\{[^}]*\}\}`)
	stripper := func(_ *url.URL, _, q string) (string, string, []domexec.RenderedRequest) {
		return "<div>" + stripTags.ReplaceAllString(q, "") + "</div>", "", nil
	}
	if out, _ := runCSTISim(t, stripper, cstiForms()); out.proof != nil {
		t.Fatalf("a filter that deletes {{...}} tags was reported as an engine: %+v", out.proof)
	}
}

// A page that sends the payload to its own API and renders the answer may have been evaluated by
// that API: undecided.
func TestCSTIPayloadShippedToAnAPIIsUndecided(t *testing.T) {
	api := func(u *url.URL, frag, q string) (string, string, []domexec.RenderedRequest) {
		dom := "<div>" + cstiSimEvaluate(frag) + "</div>"
		var reqs []domexec.RenderedRequest
		if frag != "" {
			reqs = append(reqs, domexec.RenderedRequest{URL: "http://app.test:8080/api?e=" + url.QueryEscape(frag), Type: "Fetch"})
		}
		return dom, "", reqs
	}
	out, _ := runCSTISim(t, api, cstiForms())
	if out.proof != nil || len(out.undecided) == 0 {
		t.Fatalf("want undecided, got proof=%+v undecided=%v", out.proof, out.undecided)
	}
}

func TestCSTIUnreflectedSourcesCostOneRender(t *testing.T) {
	silent := func(_ *url.URL, _, _ string) (string, string, []domexec.RenderedRequest) {
		return "<p>static</p>", "<p>static</p>", nil
	}
	_, sim := runCSTISim(t, silent, cstiForms())
	if sim.calls != 3 { // baseline, fragment canary, q canary
		t.Fatalf("%d renders for a page reflecting nothing, want 3", sim.calls)
	}
}

func TestCSTISourcesKeepTheOtherParametersAndCap(t *testing.T) {
	srcs, skipped := cstiSources("http://h:1/p?a=1&b=2#x")
	if len(srcs) != 3 || skipped != 0 {
		t.Fatalf("got %d sources, %d skipped", len(srcs), skipped)
	}
	if got := srcs[2].build("{{1*2}}"); got != "http://h:1/p?a=1&b=%7B%7B1%2A2%7D%7D" {
		t.Errorf("b substitution: %s", got)
	}
	if got := srcs[0].build("a b"); got != "http://h:1/p?a=1&b=2#a%20b" {
		t.Errorf("fragment: %s", got)
	}
	var qs []string
	for i := 0; i < cstiMaxQueryParams+3; i++ {
		qs = append(qs, fmt.Sprintf("p%d=1", i))
	}
	if srcs, skipped := cstiSources("http://h:1/p?" + strings.Join(qs, "&")); len(srcs) != cstiMaxQueryParams+1 || skipped != 3 {
		t.Errorf("cap: %d sources, %d skipped", len(srcs), skipped)
	}
}

func TestCSTIAuthoriseRefusesAnotherOriginAndOutOfScopePaths(t *testing.T) {
	ex := &core.Exchange{Host: "app.test", Port: 8080, Path: "/p?q=1"}
	if err := cstiAuthorise(nil, ex, "http://app.test:8080/p?q=%7B%7B1%7D%7D#x"); err != nil {
		t.Errorf("same origin refused: %v", err)
	}
	for _, bad := range []string{"http://evil.test:8080/p", "https://app.test:8080/p", "http://app.test:9090/p"} {
		if cstiAuthorise(nil, ex, bad) == nil {
			t.Errorf("%s was authorised", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Live twins: the vulnapp CSTI pages through a real browser.
// ---------------------------------------------------------------------------

func TestCSTIAgainstTheVulnappTwinsInABrowser(t *testing.T) {
	if !chromeOnPath() {
		domexectest.Skip(t, "no Chrome on PATH: the CSTI twins are untested")
	}
	srv := httptest.NewServer(vulnapp.Handler())
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	browser, err := sharedBrowserProvider().Browser(ctx)
	if err != nil {
		t.Fatalf("browser: %v", err)
	}
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	var checked int
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row != "Client-side template injection" {
			continue
		}
		checked++
		e := e
		t.Run(e.Path, func(t *testing.T) {
			ex := &core.Exchange{Host: u.Hostname(), Port: uint16(port), Path: e.Path}
			env := cstiEnv{
				render: browser,
				served: func(ctx context.Context, target string) (string, bool) {
					body, err := httpGetBody(ctx, target)
					return body, err == nil
				},
				authorise: func(target string) error { return cstiAuthorise(nil, ex, target) },
			}
			out, err := auditCSTI(ctx, env, exchangeURL(ex), cstiForms())
			if err != nil {
				t.Fatalf("audit: %v", err)
			}
			if e.Safe {
				if out.proof != nil {
					t.Errorf("reported against a safe page (%s): %+v", e.Note, out.proof)
				}
				if len(out.undecided) != 0 {
					t.Errorf("a safe page was left undecided: %v", out.undecided)
				}
				return
			}
			if out.proof == nil {
				t.Fatalf("missed (%s); undecided=%v", e.Note, out.undecided)
			}
			t.Logf("%s via %s: %q -> %s, confirmed by %q -> %s", out.proof.family, out.proof.source,
				out.proof.first.payload, out.proof.first.expected, out.proof.second.payload, out.proof.second.expected)
		})
	}
	if checked < 6 {
		t.Fatalf("only %d CSTI endpoints in the manifest", checked)
	}
}

func httpGetBody(ctx context.Context, target string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}
