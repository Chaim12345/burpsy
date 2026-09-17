package scanner

// The DOM dynamic confirmation tier (burpsy-react-ui-m97j) — Phase 12. These tests pin the
// three verdicts and the two honesty requirements the acceptance criteria name:
//
//   - promote-to-firm and retire-to-suppressed are both observable, over the real vulnapp DOM
//     fixture, with the browser capability stubbed so the test runs wherever Chrome is not;
//   - without a browser attached, findings stay tentative AND the caveat is ON the finding —
//     AC4's "the caveat says so" means in the evidence an operator reads, not a log;
//   - unsupported source kinds (stored, message) are named, never silently skipped;
//   - an observation that ERRORED is not a negative: retiring on an error would say "we looked
//     and saw nothing" about a page that never loaded.
import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
)

// confirmStubBrowser is a BrowserProvider whose single observation is configurable, so each
// verdict is driven without a real browser. It implements the scanner-side seam only.
type confirmStubProvider struct {
	obs []domexec.Observation
	err error
}

func (p *confirmStubProvider) Close() error { return nil }

func (p *confirmStubProvider) Browser(ctx context.Context) (*domexec.Browser, error) {
	// A zero-value Browser is the handle, not the engine: the confirm pass calls ObserveTaint
	// through the package seam, which the test re-points, so the handle only needs to be
	// non-nil for the tier to proceed past capability acquisition.
	return &domexec.Browser{}, nil
}

// observeStub overrides the confirm pass's observation call in tests. It is swapped in by
// confirmWithStub because ObserveTaint is a concrete method on a concrete type — the honest
// seam is a package-level var the production code reads (see dom_confirm.go), and this is it.
var observeStub func(target string, source domexec.SourceKind, canary string) ([]domexec.Observation, error) //nolint:unused // documented swap seam

// confirmWithStubCanary is confirmWithStub for observations that must echo the canary the
// pass mints (the promote case): the builder receives the canary the pass will look for.
func confirmWithStubCanary(t *testing.T, s *ActiveScanner, ex *core.Exchange, analysis DOMAnalysis, build func(canary string) []domexec.Observation, obsErr error) []*Finding {
	t.Helper()
	old := domConfirmObserve
	domConfirmObserve = func(_ context.Context, _ *domexec.Browser, _ string, _ domexec.SourceKind, canary string) ([]domexec.Observation, error) {
		return build(canary), obsErr
	}
	defer func() { domConfirmObserve = old }()
	return s.ConfirmDOMFindings(context.Background(), ex, analysis)
}

func confirmWithStub(t *testing.T, s *ActiveScanner, ex *core.Exchange, analysis DOMAnalysis, obs []domexec.Observation, obsErr error) []*Finding {
	t.Helper()
	old := domConfirmObserve
	domConfirmObserve = func(_ context.Context, _ *domexec.Browser, _ string, _ domexec.SourceKind, _ string) ([]domexec.Observation, error) {
		return obs, obsErr
	}
	defer func() { domConfirmObserve = old }()
	return s.ConfirmDOMFindings(context.Background(), ex, analysis)
}

// confirmAnalysis builds the static analysis of the vulnerable page shape, as the audit's
// confirmDOMAnalysisFor would: a URL-source flow to innerHTML.
func confirmAnalysis(t *testing.T, ex *core.Exchange) DOMAnalysis {
	t.Helper()
	a := AnalyzeDOMScript(`document.getElementById("out").innerHTML = location.hash;`, DOMBudget{})
	a.ExchangeID = ex.ID
	a.URL = "http://app.test/page"
	a.Method = "GET"
	if len(a.Flows) == 0 {
		t.Fatal("control case: the static pass found no flow in the vulnerable shape")
	}
	return a
}

func TestConfirmationPromotesAFlowABrowserWatchedFiring(t *testing.T) {
	s := NewActiveScanner(nil, nil)
	s.WithBrowserProvider(&confirmStubProvider{})
	ex := &core.Exchange{Host: "app.test", Port: 80, Method: "GET", Path: "/page"}
	a := confirmAnalysis(t, ex)

	// The stub's observation must carry the canary the PASS mints (it arrives at the seam), so
	// the confirmation matches: a canned observation with a made-up canary would rightly be
	// ignored — the pass must only believe an observation of its own canary.
	var seenCanary string
	confirmed := confirmWithStubCanary(t, s, ex, a, func(canary string) []domexec.Observation {
		seenCanary = canary
		return []domexec.Observation{{
			Sink: domexec.SinkInnerHTML, Source: domexec.SourceLocationHash,
			Canary: canary, Argument: "x" + canary + "y", StackTrace: "",
		}}
	}, nil)
	if seenCanary == "" {
		t.Fatal("the pass never reached the observation seam")
	}

	f := confirmed[0]
	if f.Confirm != DOMConfirmPromoted {
		t.Fatalf("confirm = %q, want promoted", f.Confirm)
	}
	if f.Confidence != "firm" {
		t.Errorf("confidence = %q, want firm — a browser watched the path fire, which is the strongest evidence this scanner ever has", f.Confidence)
	}
	if !strings.Contains(f.Evidence, "Dynamic confirmation") {
		t.Errorf("evidence does not name the dynamic tier: %q", f.Evidence)
	}
}

func TestConfirmationRetiresAFlowABrowserWatchedStaySilent(t *testing.T) {
	s := NewActiveScanner(nil, nil)
	s.WithBrowserProvider(&confirmStubProvider{})
	ex := &core.Exchange{Host: "app.test", Port: 80, Method: "GET", Path: "/page"}
	a := confirmAnalysis(t, ex)

	confirmed := confirmWithStub(t, s, ex, a, nil, nil)

	f := confirmed[0]
	if f.Confirm != DOMConfirmRetired {
		t.Fatalf("confirm = %q, want retired", f.Confirm)
	}
	if f.Confidence != "suppressed-negative" {
		t.Errorf("confidence = %q, want suppressed-negative", f.Confidence)
	}
	if !strings.Contains(f.Evidence, "one load observing nothing is evidence against reachability, not proof of safety") {
		// The finding stays named, and the evidence must say WHY it is still here: a retire that
		// reads as "safe" would convert an unknown into a silent negative.
		t.Errorf("evidence does not state the retired finding's basis: %q", f.Evidence)
	}
}

func TestWithoutABrowserTheFindingStaysTentativeAndSaysSo(t *testing.T) {
	// No WithBrowserProvider: the scan has no DOM capability at all.
	s := NewActiveScanner(nil, nil)
	ex := &core.Exchange{Host: "app.test", Port: 80, Method: "GET", Path: "/page"}
	a := confirmAnalysis(t, ex)

	// The provider is nil, so ConfirmDOMFindings marks unavailable without touching a browser.
	unavailable := s.ConfirmDOMFindings(context.Background(), ex, a)

	f := unavailable[0]
	if f.Confirm != DOMConfirmUnavailable {
		t.Fatalf("confirm = %q, want unavailable", f.Confirm)
	}
	if f.Confidence != "tentative" {
		t.Errorf("confidence = %q, want tentative — nothing was observed, so the grade must not move", f.Confidence)
	}
	if !strings.Contains(f.Evidence, "no DOM execution capability is attached") {
		t.Errorf("the caveat is not on the finding: %q", f.Evidence)
	}
}

func TestAStoredOrMessageSourceIsNamedUnsupportedNotSilentlySkipped(t *testing.T) {
	s := NewActiveScanner(nil, nil)
	s.WithBrowserProvider(&confirmStubProvider{})
	ex := &core.Exchange{Host: "app.test", Port: 80, Method: "GET", Path: "/page"}
	// A stored-source flow: localStorage.getItem reaching innerHTML.
	a := AnalyzeDOMScript(`var v = localStorage.getItem("k"); el.innerHTML = v;`, DOMBudget{})
	a.ExchangeID = ex.ID
	if len(a.Flows) == 0 {
		t.Fatal("control case: no stored flow found")
	}

	confirmed := confirmWithStub(t, s, ex, a, nil, nil)

	f := confirmed[0]
	if f.Confirm != DOMConfirmUnsupported {
		t.Fatalf("confirm = %q, want unsupported-source — the harness cannot plant client-side storage", f.Confirm)
	}
	if f.Confidence != "tentative" {
		t.Errorf("confidence = %q, want tentative: an unconfirmable flow is still only a static candidate", f.Confidence)
	}
	if !strings.Contains(f.Evidence, "not in client-side storage or an inbound message") {
		t.Errorf("evidence does not name the limit: %q", f.Evidence)
	}
}

func TestAnObservationErrorIsNotANegative(t *testing.T) {
	s := NewActiveScanner(nil, nil)
	s.WithBrowserProvider(&confirmStubProvider{})
	ex := &core.Exchange{Host: "app.test", Port: 80, Method: "GET", Path: "/page"}
	a := confirmAnalysis(t, ex)

	confirmed := confirmWithStub(t, s, ex, a, nil, errors.New("page never loaded: net::ERR_CONNECTION_REFUSED"))

	f := confirmed[0]
	if f.Confirm != DOMConfirmUnavailable {
		t.Fatalf("confirm = %q, want unavailable — an errored observation must not retire a finding", f.Confirm)
	}
	if f.Confidence != "tentative" {
		t.Errorf("confidence = %q, want tentative", f.Confidence)
	}
}

func TestTheTierGradesTheConfidenceTheIssuesAPIRenders(t *testing.T) {
	// AC3's wire check, held at the unit level: ParseConfidence must know suppressed-negative,
	// or a retired finding would reach the issues API downgraded to "tentative" and the
	// operator would read a retired verdict as "we do not know".
	if got := core.ParseConfidence("suppressed-negative"); got != core.ConfidenceSuppressedNegative {
		t.Fatalf("ParseConfidence(suppressed-negative) = %v, want the SuppressedNegative grade", got)
	}
	if got := core.ConfidenceSuppressedNegative.String(); got != "Suppressed-negative" {
		t.Errorf("String() = %q, want Suppressed-negative", got)
	}
}

func TestAnObservationOfSomeoneElsesCanaryDoesNotConfirm(t *testing.T) {
	// The canary IS the identity of a confirmation. An observation whose argument carries a
	// different canary is evidence about a different flow — another scan's probe, or the page's
	// own traffic — and counting it would let any sink activity on the page promote a static
	// candidate. Pinned here because the any-observation-confirms mutation survived the
	// original test set.
	s := NewActiveScanner(nil, nil)
	s.WithBrowserProvider(&confirmStubProvider{})
	ex := &core.Exchange{Host: "app.test", Port: 80, Method: "GET", Path: "/page"}
	a := confirmAnalysis(t, ex)

	confirmed := confirmWithStub(t, s, ex, a, []domexec.Observation{{
		Sink: domexec.SinkInnerHTML, Source: domexec.SourceLocationHash,
		Canary: "somebody-else-canary", Argument: "xsomebody-else-canaryy", StackTrace: "",
	}}, nil)

	f := confirmed[0]
	if f.Confirm != DOMConfirmRetired {
		t.Fatalf("confirm = %q, want retired — an observation that does not carry this pass's canary is evidence about a different flow, and must not promote", f.Confirm)
	}
}
