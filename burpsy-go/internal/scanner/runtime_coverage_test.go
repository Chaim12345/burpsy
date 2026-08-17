package scanner

// Runtime scanner coverage: the real scanner, against a real running target, over real HTTP.
//
// # Why this file exists at all
//
// Every other measure of this scanner's coverage turned out to measure something else.
//
//   - NativeCheckRegistry reports 183 runnable rows. Runnable() is `Run != nil &&
//     DeclineReason == ""` — a non-nil function pointer. It cannot tell a detector from a stub.
//   - Statement coverage reported 76.6%, and rose when a test was added that asserts checks
//     *refuse* to run. Executing a capability guard is not exercising a detector.
//   - Grepping for symbol references produced straight false negatives, calling functions
//     unreferenced that the suite does in fact execute.
//
// So none of them answers the only question worth asking: when this scanner is pointed at an
// application that really is vulnerable, does it say so? This file answers exactly that, and
// nothing else.
//
// # The number is derived, never pinned
//
// internal/vulnapp declares each endpoint and the catalog row it exposes. The assertions here
// come from that declaration, so coverage grows by planting another vulnerability rather than by
// editing a constant. Six files in this package used to carry hand-maintained totals; a wrong
// total failed the build while a check that could never fire passed it. A count nobody has to
// update cannot drift.
//
// # Both directions, or it proves nothing
//
// Firing on a vulnerable endpoint shows the detector works. Staying silent on the *safe*
// counterpart shows it keys on evidence rather than on reflection — the failure this codebase
// cares about most, because a detector that reports every echo is indistinguishable from a
// working one until someone reads the findings.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// runtimeTarget is a live vulnapp instance plus a store seeded from real traffic to it.
type runtimeTarget struct {
	srv       *httptest.Server
	host      string
	port      uint16
	store     *core.TrafficStore
	scan      *ActiveScanner
	exchanges map[string]core.ExchangeID // endpoint path -> seeded exchange
	// lastRequestsSent carries the probe count of the most recent findingsFor call, so the
	// request-budget test can read it without every caller threading an extra return value.
	lastRequestsSent uint32
	// chrome records whether a browser was available, so DOM manifest entries are asserted or
	// skipped by name rather than quietly passing.
	chrome bool
	// domScan is the browser-enabled scanner, nil when no Chrome is available.
	domScan *ActiveScanner
}

// startRuntimeTarget serves vulnapp, requests every declared endpoint over real HTTP, and stores
// each request/response pair as the scanner would have captured it through the proxy.
func startRuntimeTarget(t *testing.T) *runtimeTarget {
	t.Helper()

	srv := httptest.NewServer(vulnapp.Handler())
	t.Cleanup(srv.Close)

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse target port: %v", err)
	}

	rt := &runtimeTarget{
		srv: srv, host: host, port: port,
		store:     core.NewTrafficStore(),
		exchanges: map[string]core.ExchangeID{},
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		// Redirects must not be followed: the open-redirect endpoint's 302 *is* the evidence,
		// and a client that chased it would store the destination instead.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	for _, e := range vulnapp.Vulnerabilities() {
		rt.seed(t, client, e)
	}
	if len(rt.exchanges) == 0 {
		t.Fatal("no exchanges were captured from the target; every assertion below would be vacuous")
	}

	// Two scanners over one store. Auditing every endpoint with the 48 DOM rows drives a browser
	// for each, which cost ~50s per endpoint and told us nothing about the ten non-DOM rows.
	rt.scan = NewActiveScanner(rt.store, zap.NewNop()).
		WithSender(sender.NewSender(nil)).
		WithStoredLedger(NewStoredLedger()).
		WithConfig(runtimeScanConfig())

	rt.chrome = chromeOnPath()
	if rt.chrome {
		domCfg := runtimeScanConfig()
		domCfg.CheckDOM = true
		// Headless unless BURPSY_DOM_HEADED=1, which is for watching a flow live.
		headed := os.Getenv("BURPSY_DOM_HEADED") == "1"
		rt.domScan = NewActiveScanner(rt.store, zap.NewNop()).
			WithSender(sender.NewSender(nil)).
			WithStoredLedger(NewStoredLedger()).
			WithBrowserProvider(NewLazyBrowserProvider(domexec.Options{Headed: headed})).
			WithConfig(domCfg)
		t.Cleanup(func() { _ = rt.domScan.CloseCapabilities() })
	}
	return rt
}

// scannerFor picks the DOM-enabled scanner only for endpoints whose row is a DOM row.
func (rt *runtimeTarget) scannerFor(dom bool) *ActiveScanner {
	if dom && rt.domScan != nil {
		return rt.domScan
	}
	return rt.scan
}

func chromeOnPath() bool {
	for _, name := range []string{"chromium", "google-chrome", "google-chrome-stable", "chrome"} {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}

// seed performs one real request and records the exchange, mirroring what the proxy captures.
func (rt *runtimeTarget) seed(t *testing.T, client *http.Client, e vulnapp.Endpoint) {
	t.Helper()

	method := e.Method
	if method == "" {
		method = http.MethodGet
	}
	body, contentType := e.Body, e.ContentType
	if body == "" && method == http.MethodPost {
		// The form-field rows are reached through form parameters, so a POST that declares no
		// body of its own still needs one for the enumerator to find points in.
		body, contentType = "user=seed&pass=seed", "application/x-www-form-urlencoded"
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rt.srv.URL+e.Path, reader)
	if err != nil {
		t.Fatalf("build request for %s: %v", e.Path, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// An Origin is needed for the CORS row to have anything to reflect.
	req.Header.Set("Origin", "https://evil.example")

	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("request %s: %v", e.Path, err)
	}
	defer func() { _ = res.Body.Close() }()

	rawReq := buildRawRequest(method, e.Path, rt.host, rt.port, body, contentType)
	rawResp := buildRawResponse(t, res)

	reqID, err := rt.store.Put([]byte(rawReq), core.DirectionRequest)
	if err != nil {
		t.Fatalf("store request for %s: %v", e.Path, err)
	}
	respID, err := rt.store.Put([]byte(rawResp), core.DirectionResponse)
	if err != nil {
		t.Fatalf("store response for %s: %v", e.Path, err)
	}
	ex := &core.Exchange{
		Request: reqID, Response: &respID,
		Host: rt.host, Port: rt.port, TLS: false,
		Method: method, Path: e.Path,
	}
	rt.store.AddExchange(ex)
	rt.exchanges[e.Path] = ex.ID
}

func buildRawRequest(method, path, host string, port uint16, body, contentType string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", net.JoinHostPort(host, fmt.Sprint(port)))
	b.WriteString("Origin: https://evil.example\r\n")
	if body != "" {
		// The stored bytes are what the insertion-point enumerator parses, so a mislabelled
		// content type here would have it look for form parameters in an XML document.
		if contentType == "" {
			contentType = "application/x-www-form-urlencoded"
		}
		fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

func buildRawResponse(t *testing.T, res *http.Response) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", res.StatusCode, http.StatusText(res.StatusCode))
	keys := make([]string, 0, len(res.Header))
	for k := range res.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range res.Header[k] {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	// io.ReadAll, not a single Read.
	//
	// A bare res.Body.Read fills the buffer with whatever one read returns, which for a chunked or
	// slow response is the first chunk and not the body. The seeded baseline would then be a prefix
	// of the real one, and every differential comparison in the scan would be against a truncated
	// reference — silently, since a short read is not an error.
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	b.Write(body)
	return b.String()
}

// runtimeScanConfig turns on the families a runtime scan of this target can exercise.
//
// # What is OFF, and the row count it costs
//
// This matters because it bounds what this file can claim. The switches below admit roughly 103 of
// the 183 catalog rows; the omissions are:
//
//   - CheckDOM (48 rows) — needs a headless Chrome. capability_handles_live_test.go gates on a
//     Chrome binary and this file has no such gate, so enabling it would make the corpus fail on a
//     machine without one rather than skip. Worth adding behind the same guard.
//   - CheckExtendedActive (22 rows) — of these only "Out-of-band resource load (HTTP)", the three
//     External-service-interaction rows and "TLS certificate" need the network (a collaborator
//     binary, or the tlsx subprocess). The other ~17 are network-free and SHOULD be enabled here;
//     an earlier version of this comment claimed the whole family needed outbound internet, which
//     was simply wrong.
//   - CheckStored (10 rows) — the manifest declares no stored vulnerability yet, so turning it on
//     would exercise the planting half against endpoints that never surface a canary.
//   - CheckSSRF, CheckXXE — subsumed by CheckExtendedActive's gate.
//   - CheckCorpus — BCheck corpus, a separate evaluator architecture.
//   - CheckExtendedCoverage — admits declined rows, of which there are now none.
//
// So the honest reading of this file's result is "the rows these switches admit, against the
// vulnerabilities the manifest declares" — not a statement about the catalog.
func runtimeScanConfig() *ScanConfig {
	return &ScanConfig{
		MaxConcurrency: 4,
		// Generous: with CheckDOM on, every audit drives a real browser, and a 20s budget was
		// spent before the header checks ran — CORS stopped firing for lack of time, not evidence.
		Timeout:                 5 * time.Minute,
		CheckSqli:               true,
		CheckXss:                true,
		CheckPathTraversal:      true,
		CheckJwtWeak:            true,
		CheckJSVulns:            true,
		CheckHeaders:            true,
		CheckCachePoisoning:     true,
		CheckReflectionProbes:   true,
		CheckHostDiscovery:      true,
		CheckResponseDependence: true,
		CheckPassivePosture:     true,
		CheckPassiveAnalysis:    true,
		CheckActiveInjection:    true,
		// Admits the 22 checks_remaining.go rows plus the 16 in checks_final.go. Five of those
		// need outbound network (the OOB row, three external-service-interaction rows, TLS
		// certificate); the rest are network-free and are exercised here.
		CheckExtendedActive: true,
	}
}

// findingsFor audits one seeded endpoint with the real engine and returns the row names reported.
// dom selects the browser-enabled scanner, so non-DOM endpoints never pay for a page load.
func (rt *runtimeTarget) findingsFor(t *testing.T, path string, dom bool) map[string]*Finding {
	t.Helper()
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scan := rt.scannerFor(dom)
	outcome, findings := scan.AuditWithin(ctx, id, scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed outright: %s", path, outcome.Error)
	}
	rt.lastRequestsSent = outcome.RequestsSent
	byRow := make(map[string]*Finding, len(findings))
	for _, f := range findings {
		if f != nil {
			byRow[f.Name] = f
		}
	}
	return byRow
}

// Request accounting, copied from ZAP's convention rather than invented.
//
// ZAP's shared active-scan test base asserts every rule against a per-strength request budget
// (ActiveScannerTestUtils.shouldSendReasonableNumberOfMessagesIn[Strength], with per-parameter
// limits of 6/12/24/75 for LOW/MEDIUM/HIGH/INSANE). The assertion is doing two jobs at once, and
// both matter here:
//
//   - An upper bound catches a check that has become a request amplifier. Nothing else in this
//     suite would notice a probe loop that grew by an order of magnitude; the tests would still
//     pass, just slower.
//   - A lower bound of one catches the opposite and worse case: a scan that sent nothing at all.
//     Every "no finding" assertion in this file is vacuous if no probe left the process, so
//     without this the safe-counterpart suite could pass by doing nothing.
//
// The budget is per audited endpoint rather than per parameter because burpsy's engine reports
// RequestsSent per item, and it is deliberately loose: this is a runaway detector, not a
// performance target.
func TestAnAuditSendsProbesAndStaysWithinARequestBudget(t *testing.T) {
	const budgetPerEndpoint = 2000

	rt := startRuntimeTarget(t)
	var total uint32
	var audited int

	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row == "" {
			continue
		}
		e := e
		t.Run(e.Path, func(t *testing.T) {
			rt.lastRequestsSent = 0
			rt.findingsFor(t, e.Path, e.DOM)
			sent := rt.lastRequestsSent
			audited++
			total += sent

			if sent == 0 {
				t.Fatalf("the audit of %s sent no probes at all. Every assertion about what this "+
					"endpoint does or does not report is vacuous, because nothing was asked of it.", e.Path)
			}
			if sent > budgetPerEndpoint {
				t.Errorf("the audit of %s sent %d probes, budget %d. A check has become a request "+
					"amplifier; nothing else in this suite would notice.", e.Path, sent, budgetPerEndpoint)
			}
		})
	}
	if audited == 0 {
		t.Fatal("no endpoint was audited")
	}
	t.Logf("request accounting: %d probes across %d endpoints (mean %d)", total, audited, total/uint32(audited))
}

// The headline assertion: every vulnerability vulnapp declares must actually be reported.
func TestTheScannerDetectsWhatTheTargetDeclaresItIsVulnerableTo(t *testing.T) {
	rt := startRuntimeTarget(t)

	// A row name that does not exist in the catalog would exempt its endpoint from every
	// assertion here, so the manifest is resolved before anything is audited.
	catalog := map[string]bool{}
	for _, d := range NativeCheckRegistry() {
		catalog[d.Name] = true
	}
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row != "" && !catalog[e.Row] {
			t.Fatalf("vulnapp declares %q for %s, which is not a catalog row name; the assertion would never run",
				e.Row, e.Path)
		}
	}

	var demonstrated, missed []string
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row == "" || e.Safe {
			continue
		}
		e := e
		t.Run(e.Row+" via "+e.Path, func(t *testing.T) {
			if e.DOM && !rt.chrome {
				t.Skip("no Chrome on PATH: this DOM row is NOT exercised in this run")
			}
			got := rt.findingsFor(t, e.Path, e.DOM)
			if _, fired := got[e.Row]; !fired {
				missed = append(missed, e.Row+" @ "+e.Path)
				t.Errorf("the target is vulnerable here (%s) but %q was not reported.\nrows reported instead: %s",
					e.Note, e.Row, joinRows(got))
				return
			}
			demonstrated = append(demonstrated, e.Row)
		})
	}

	// The number this project reports as coverage. Pinned so it cannot drift downward silently:
	// a check that stops firing takes a manifest row with it, and a demonstrated count that only
	// ever appears in a log line is not a claim anything defends.
	//
	// It counts DISTINCT catalog rows, not endpoints - two endpoints proving one row is one row's
	// worth of evidence, and conflating them is how 8 rows once got reported as 10.
	distinct := map[string]bool{}
	for _, r := range demonstrated {
		distinct[r] = true
	}
	const wantDemonstrated = 21
	t.Logf("runtime detection: %d distinct catalog rows demonstrated across %d endpoints, %d missed",
		len(distinct), len(demonstrated), len(missed))
	if len(missed) == 0 && len(distinct) < wantDemonstrated {
		t.Errorf("distinct rows demonstrated = %d, want at least %d. Nothing failed, so a check did "+
			"not regress - a manifest entry was removed or renamed, which quietly lowers the number "+
			"this project publishes as its coverage", len(distinct), wantDemonstrated)
	}
}

// The other direction: the safe counterparts must stay quiet for their row.
//
// Each case also audits the VULNERABLE twin in the same run and requires it to fire. Without that,
// silence on the safe endpoint is ambiguous: a check whose probes never landed — a send that failed,
// an insertion point that was not enumerated, a switch left off — produces exactly the same "no
// finding" as a check that looked and correctly found nothing. Pairing them makes the assertion mean
// "this check works AND does not fire here", which is the only version worth having.
func TestTheScannerStaysQuietOnTheSafeCounterparts(t *testing.T) {
	rt := startRuntimeTarget(t)

	// Row -> a vulnerable endpoint for it, so each safe case can prove the row is live.
	vulnerableTwin := map[string]string{}
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row != "" && !e.Safe {
			if _, seen := vulnerableTwin[e.Row]; !seen {
				vulnerableTwin[e.Row] = e.Path
			}
		}
	}

	var checked int
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row == "" || !e.Safe {
			continue
		}
		checked++
		e := e
		t.Run(e.Row+" via "+e.Path, func(t *testing.T) {
			if e.DOM && !rt.chrome {
				t.Skip("no Chrome on PATH: this DOM row is NOT exercised in this run")
			}
			twin, ok := vulnerableTwin[e.Row]
			if !ok {
				t.Fatalf("no vulnerable endpoint declared for %q, so silence here proves nothing", e.Row)
			}
			if fired := rt.findingsFor(t, twin, e.DOM); fired[e.Row] == nil {
				t.Fatalf("%q did not fire against its vulnerable twin %s in this run, so its silence "+
					"on %s is not evidence of anything — the check may simply not be working here",
					e.Row, twin, e.Path)
			}

			got := rt.findingsFor(t, e.Path, e.DOM)
			if f, fired := got[e.Row]; fired {
				t.Errorf("%q was reported against a safe endpoint (%s). Evidence given: %q.\n"+
					"This endpoint reflects input without the defect, so the detector is keying on "+
					"reflection rather than on evidence — a false positive with a name attached.",
					e.Row, e.Note, f.Evidence)
			}
		})
	}
	if checked == 0 {
		t.Fatal("no safe counterpart was exercised; the false-positive half of the corpus is missing")
	}
}

// The manifest has to keep both halves. A vulnerable endpoint with no safe twin can pass by
// firing on reflection alone, which is the exact failure the safe half exists to catch.
func TestEveryDetectionClaimHasASafeCounterpart(t *testing.T) {
	vulnerable := map[string][]string{}
	safe := map[string]bool{}
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row == "" {
			continue
		}
		if e.Safe {
			safe[e.Row] = true
			continue
		}
		vulnerable[e.Row] = append(vulnerable[e.Row], e.Path)
	}
	if len(vulnerable) == 0 {
		t.Fatal("the manifest declares no vulnerabilities")
	}

	// Rows whose safe counterpart cannot be built without changing what the endpoint IS.
	// Each needs a reason, because the alternative is an unexplained gap.
	noSafeTwin := map[string]string{
		"Cross-origin resource sharing: arbitrary origin trusted": "a safe twin is an endpoint with no CORS policy, which is covered by every other endpoint here",
		"Database connection string disclosed":                    "a safe twin is a response without a connection string, which is every other endpoint here",
	}

	for row, paths := range vulnerable {
		if safe[row] {
			continue
		}
		if reason, ok := noSafeTwin[row]; ok {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%q is exempted from needing a safe counterpart with no reason", row)
			}
			continue
		}
		t.Errorf("%q is claimed vulnerable at %v but has no safe counterpart, so firing on plain "+
			"reflection would satisfy the claim", row, paths)
	}
}

func joinRows(byRow map[string]*Finding) string {
	if len(byRow) == 0 {
		return "(none)"
	}
	names := make([]string, 0, len(byRow))
	for n := range byRow {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
