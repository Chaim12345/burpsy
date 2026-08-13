package scanner

// The probe harness against a real local HTTP server, so the I/O path is exercised end to
// end: baseline capture, insertion-point enumeration, payload application, authorised send,
// and classification.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// harnessAgainst starts a server, seeds an exchange for path, and returns a CheckContext
// wired to a real sender pointed at it.
func harnessAgainst(t *testing.T, handler http.HandlerFunc, path string) *CheckContext {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	store := core.NewTrafficStore()
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s:%d\r\n\r\n", path, host, port)
	reqID, err := store.Put([]byte(rawReq), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nseed"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: host, Port: port,
		TLS: false, Method: "GET", Path: path}
	store.AddExchange(ex)

	s := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(nil))
	return NewCheckContext(s, ex, nil)
}

func TestHarnessCapturesABaselineAndEnumeratesPoints(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "you sent q=%s", r.URL.Query().Get("q"))
	}, "/search?q=hello")

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	if h.Baseline().Status != 200 {
		t.Errorf("baseline status = %d, want 200", h.Baseline().Status)
	}
	if !strings.Contains(h.Baseline().Body, "q=hello") {
		t.Errorf("baseline body did not come from the live server: %q", h.Baseline().Body)
	}
	if len(h.Points()) == 0 {
		t.Fatal("no insertion points enumerated for a URL with a query parameter")
	}
	var sawQ bool
	for _, p := range h.Points() {
		if p.Name == "q" {
			sawQ = true
		}
	}
	if !sawQ {
		t.Errorf("the q parameter was not enumerated: %+v", h.Points())
	}
}

// No sender means no active probe. Returning a harness anyway would let a caller report
// "no evidence" for work that never left the process.
func TestHarnessRefusesWithoutASender(t *testing.T) {
	cc := postureFixture(t, "GET /?q=1 HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), false)
	if _, err := NewProbeHarness(context.Background(), cc, nil); err == nil {
		t.Fatal("NewProbeHarness succeeded with no sender")
	}
}

func TestHarnessRefusesWithoutAnExchange(t *testing.T) {
	if _, err := NewProbeHarness(context.Background(), &CheckContext{}, nil); err == nil {
		t.Fatal("NewProbeHarness succeeded with no exchange")
	}
}

// A dead server means no baseline, which must fail rather than yield a harness whose
// comparisons are all against an empty string.
func TestHarnessRefusesWhenNoBaselineCanBeCaptured(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {}, "/x")
	// Point the exchange at a port nothing is listening on.
	cc.Exchange.Port = 1
	if _, err := NewProbeHarness(context.Background(), cc, nil); err == nil {
		t.Fatal("NewProbeHarness succeeded with no reachable baseline")
	}
}

func TestHarnessSendsAPayloadIntoTheNamedPoint(t *testing.T) {
	var seen string
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Query().Get("q")
		fmt.Fprintf(w, "echo:%s", seen)
	}, "/search?q=hello")

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	point := h.Points()[0]
	res, err := h.Send(context.Background(), point, "INJECTED")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if seen != "INJECTED" {
		t.Errorf("server saw q=%q, want INJECTED", seen)
	}
	if !strings.Contains(res.Body, "INJECTED") {
		t.Errorf("probe response did not carry the payload: %q", res.Body)
	}
}

// The error-signature path: a server that only errors when a quote is injected is exactly
// the case ClassifyErrorEvidence exists for.
func TestHarnessErrorSignatureProbeFindsAnIntroducedError(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "'") {
			fmt.Fprint(w, "You have an error in your SQL syntax near ''")
			return
		}
		fmt.Fprint(w, "results for "+q)
	}, "/search?q=hello")

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	probes := h.ProbeErrorSignatures(context.Background(), h.Points()[0], []string{"'"}, SQLErrorSignatures)
	best, confirmed := BestEvidence(probes)
	if !confirmed || best.Evidence != InjectionEvidenceErrorSignature {
		t.Fatalf("best = %+v confirmed=%v, want an introduced error signature", best, confirmed)
	}
	if !strings.Contains(best.Detail, "introduced") {
		t.Errorf("detail should name the introduced signature: %q", best.Detail)
	}
}

// The endpoint that always errors: the signature is in the baseline, so it proves nothing.
func TestHarnessErrorSignatureProbeIsInconclusiveOnAnAlwaysErroringEndpoint(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "You have an error in your SQL syntax, always")
	}, "/search?q=hello")

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	probes := h.ProbeErrorSignatures(context.Background(), h.Points()[0], []string{"'"}, SQLErrorSignatures)
	best, confirmed := BestEvidence(probes)
	if confirmed {
		t.Fatalf("an always-erroring endpoint produced a confirmation: %+v", best)
	}
	if best.Evidence != InjectionEvidenceInconclusive {
		t.Fatalf("evidence = %v, want InjectionEvidenceInconclusive", best.Evidence)
	}
	if !strings.Contains(best.Detail, "already in the baseline") {
		t.Errorf("detail should say the signature pre-existed: %q", best.Detail)
	}
}

func TestHarnessEvaluationProbeSeparatesEvaluationFromEcho(t *testing.T) {
	// Evaluating server: computes the arithmetic.
	evaluating := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "7*6") {
			fmt.Fprint(w, "result: 42")
			return
		}
		fmt.Fprint(w, "result: none")
	}, "/calc?q=1")
	h, err := NewProbeHarness(context.Background(), evaluating, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	got := h.ProbeEvaluation(context.Background(), h.Points()[0], `".(7*6)."`, ArithmeticProofProduct())
	if got.Evidence != InjectionEvidenceEvaluated {
		t.Fatalf("evaluating server gave %v, want InjectionEvidenceEvaluated (%s)", got.Evidence, got.Detail)
	}

	// Echoing server: reflects the payload verbatim and computes nothing.
	echoing := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "you sent "+r.URL.Query().Get("q"))
	}, "/calc?q=1")
	h2, err := NewProbeHarness(context.Background(), echoing, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	got = h2.ProbeEvaluation(context.Background(), h2.Points()[0], `".(7*6)."`, ArithmeticProofProduct())
	if got.Evidence == InjectionEvidenceEvaluated {
		t.Fatalf("an echoing server was reported as evaluating: %s", got.Detail)
	}
}

func TestHarnessBooleanProbeNeedsBothHalves(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		switch {
		case strings.Contains(q, "1=2"):
			fmt.Fprint(w, "no records")
		default:
			fmt.Fprint(w, "welcome admin")
		}
	}, "/u?q=admin")

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	got := h.ProbeBoolean(context.Background(), h.Points()[0], "admin' and 1=1--", "admin' and 1=2--")
	if got.Evidence != InjectionEvidenceBooleanDifferential {
		t.Fatalf("got %v (%s), want InjectionEvidenceBooleanDifferential", got.Evidence, got.Detail)
	}
}

func TestHarnessTimingProbeObservesADelayAgainstTheBaseline(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "sleep") {
			time.Sleep(700 * time.Millisecond)
		}
		fmt.Fprint(w, "ok")
	}, "/t?q=1")

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	got := h.ProbeTiming(context.Background(), h.Points()[0], "pg_sleep(1)--sleep", 700*time.Millisecond)
	if got.Evidence != InjectionEvidenceTiming {
		t.Fatalf("got %v (%s), want InjectionEvidenceTiming", got.Evidence, got.Detail)
	}
}

// The property the harness exists to protect: a probe that never reached the target must be
// inconclusive, never "no evidence". Reporting an unsent probe as clean is the exact
// dishonest counting this project forbids.
func TestAnUnsentProbeIsInconclusiveNotCleanEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "baseline ok")
	}))
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("port: %v", err)
	}

	store := core.NewTrafficStore()
	reqID, _ := store.Put([]byte(fmt.Sprintf("GET /s?q=1 HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)), core.DirectionRequest)
	respID, _ := store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nseed"), core.DirectionResponse)
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: host, Port: port, Method: "GET", Path: "/s?q=1"}
	store.AddExchange(ex)
	s := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(nil))
	cc := NewCheckContext(s, ex, nil)

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	// Baseline captured; now make every further send fail.
	srv.Close()

	probes := h.ProbeErrorSignatures(context.Background(), h.Points()[0], []string{"'"}, SQLErrorSignatures)
	if len(probes) != 1 {
		t.Fatalf("got %d probes, want 1", len(probes))
	}
	if probes[0].Evidence != InjectionEvidenceInconclusive {
		t.Fatalf("evidence = %v, want InjectionEvidenceInconclusive for a probe that never landed", probes[0].Evidence)
	}
	if !strings.Contains(probes[0].Detail, "not sent") {
		t.Errorf("detail should say the probe was not sent: %q", probes[0].Detail)
	}
	if _, confirmed := BestEvidence(probes); confirmed {
		t.Error("an unsent probe produced a confirmation")
	}

	// The boolean form has two sends; both failing must also be inconclusive.
	b := h.ProbeBoolean(context.Background(), h.Points()[0], "a' and 1=1--", "a' and 1=2--")
	if b.Evidence != InjectionEvidenceInconclusive {
		t.Fatalf("boolean evidence = %v, want InjectionEvidenceInconclusive", b.Evidence)
	}
}

// Coverage must carry declined points through. Asserting against an empty declined list
// passes for the wrong reason, so a synthetic entry is injected to exercise the reporting.
func TestCoverageReportsDeclinedPointsThatWereNeverTested(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}, "/c?q=1")
	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	h.declined = append(h.declined, bcheck.Declined{
		What: "request body", Reason: "multipart body: framing not modelled"})

	cov := h.Coverage(nil, 1)
	if cov.PointsDeclined != 1 {
		t.Fatalf("PointsDeclined = %d, want 1; a place the scan could not reach must be reported",
			cov.PointsDeclined)
	}
}

func TestHarnessTimingProbeReportsNoEvidenceOnAPromptEndpoint(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}, "/t?q=1")
	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	got := h.ProbeTiming(context.Background(), h.Points()[0], "pg_sleep(1)--", time.Second)
	if got.Evidence != InjectionEvidenceNone {
		t.Fatalf("got %v (%s), want InjectionEvidenceNone", got.Evidence, got.Detail)
	}
}

// Coverage must report points it could not enumerate, not silently omit them.
func TestHarnessCoverageReportsDeclinedPointsAndInconclusiveProbes(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}, "/c?q=1")
	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	probes := []InjectionProbe{
		{Evidence: InjectionEvidenceNone},
		{Evidence: InjectionEvidenceInconclusive},
	}
	cov := h.Coverage(probes, 1)
	if cov.PointsTested != 1 || cov.PayloadsSent != 2 || cov.Inconclusive != 1 {
		t.Fatalf("coverage = %+v", cov)
	}
	if cov.PointsDeclined != len(h.DeclinedPoints()) {
		t.Errorf("coverage lost the declined-point count")
	}
}

// ---------- capability handles ----------

// The whole reason the handles return errors: a check must learn "no capability" rather than
// receiving something that yields an empty result.
func TestAMissingBrowserIsAnErrorNotAnEmptyObservationSet(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), true)
	if _, err := cc.Browser(context.Background()); err == nil {
		t.Fatal("Browser() succeeded with no provider configured; a DOM check would read zero observations as clean")
	}
}

func TestAMissingStoredLedgerIsAnError(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), true)
	if _, err := cc.StoredLedger(); err == nil {
		t.Fatal("StoredLedger() succeeded with none configured; a stored check would read nothing as clean")
	}
}

func TestAnInstalledStoredLedgerIsReachableFromTheContext(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), true)
	ledger := NewStoredLedger()
	cc.Scanner.WithStoredLedger(ledger)

	got, err := cc.StoredLedger()
	if err != nil {
		t.Fatalf("StoredLedger: %v", err)
	}
	if got != ledger {
		t.Fatal("a different ledger came back")
	}
}

// The observation half of second-order threading: a canary planted against one exchange and
// seen in another must be reported, and one seen only in its own must not.
func TestObserveStoredCanariesReportsOnlyCrossExchangeSightings(t *testing.T) {
	cc := postureFixture(t, "GET /queue HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), true)
	ledger := NewStoredLedger()
	cc.Scanner.WithStoredLedger(ledger)

	// Planted against a different exchange id than the one we are about to observe.
	planted, err := ledger.Plant(cc.Exchange.ID+1, "/comment", "body")
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}
	// Rebuild the exchange so its response contains the canary.
	seen := postureFixture(t, "GET /queue HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("<li>"+planted.Token+"</li>"), true)
	seen.Scanner.WithStoredLedger(ledger)

	got := seen.Scanner.ObserveStoredCanaries(seen.Exchange)
	if len(got) != 1 {
		t.Fatalf("got %d cross-exchange sightings, want 1", len(got))
	}
	if got[0].Canary.Token != planted.Token {
		t.Errorf("wrong canary reported: %+v", got[0])
	}
}

func TestObserveStoredCanariesIsANoOpWithoutALedger(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), true)
	if got := cc.Scanner.ObserveStoredCanaries(cc.Exchange); got != nil {
		t.Fatalf("got %d observations with no ledger installed, want none", len(got))
	}
}

// A provider whose Chrome path does not exist must report that, not hand back a browser.
func TestLazyBrowserProviderReportsAMissingBinary(t *testing.T) {
	p := NewLazyBrowserProvider(domexec.Options{ChromePath: "/nonexistent/chrome-9f2a"})
	if _, err := p.Browser(context.Background()); err == nil {
		t.Fatal("Browser() succeeded with a nonexistent Chrome path")
	}
	// The failure is remembered rather than retried per call.
	if _, err := p.Browser(context.Background()); err == nil {
		t.Fatal("the second call succeeded after the first failed")
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close on a never-started provider errored: %v", err)
	}
}
