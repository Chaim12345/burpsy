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
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
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
	// chrome records whether a browser was available, so DOM manifest entries are asserted or
	// skipped by name rather than quietly passing.
	chrome bool
	// domScan is the browser-enabled scanner, nil when no Chrome is available.
	domScan *ActiveScanner
	// storedScan enables the stored rows and is driven through the deferred phase.
	storedScan *ActiveScanner
	// storedDomScan is the fourth scanner: stored rows AND a browser, for the rows whose evidence
	// only exists once a page's own script has fetched the stored value and used it. Nil when no
	// Chrome is available, which the DOM skip path already reports by name.
	//
	// It is a template rather than the scanner actually used. A stored claim is retired the instant
	// it resolves, so two test functions sharing one ledger cannot both see the same row: whichever
	// audits first consumes the claim and the second reads silence. Because this target is shared
	// across the whole binary for speed, that made the stored DOM rows order-dependent. Each audit
	// therefore gets its own ledger via storedDomScanner(), and only the browser is shared.
	storedDomScan *ActiveScanner
	// storedDomBrowsers is the one browser provider the stored-DOM phase uses.
	storedDomBrowsers BrowserProvider
	// The stored-DOM phase runs ONCE for every stored+DOM endpoint, and these hold its result.
	//
	// It used to run per audit, each with a fresh ledger, which was correct and quadratic: every
	// audit's FinishScan rendered every script-bearing page in the manifest, so 26 endpoints times
	// ~100 pages was ~2,600 browser page loads and the scanner package took 1092s. Almost none of
	// those renders could show the canary belonging to the audit that paid for them.
	//
	// One pass is also closer to what a real scan does: plant everything, then run the deferred
	// phase once. Attribution is by exchange - deferStoredClaim only resolves canaries whose origin
	// is the claim's own exchange - so a shared ledger cannot mix two endpoints' verdicts, which is
	// what the per-audit ledgers were there to prevent.
	storedDomOnce   sync.Once
	storedDomByPath map[string]map[string]*Finding
	storedDomSent   map[string]uint32
	// memo caches each endpoint's audit for this target's lifetime; see auditOnce. Guarded because
	// the subtests that read it run in parallel.
	memo   map[string]*memoisedAudit
	memoMu sync.Mutex
	// freshAudits counts audits that actually ran, as opposed to memo hits. The shared target lives
	// for the whole test binary rather than per -count iteration, so a second in-process iteration
	// is served entirely from cache; without this the coverage line would print an identical claim
	// having sent no probe at all.
	freshAudits int
	// The TLS twin of the target, for rows gated on an encrypted exchange.
	tlsSrv  *httptest.Server
	tlsHost string
	tlsPort uint16
	// listeners serve the endpoints that declare a listener of their own (Endpoint.Listener), keyed
	// by listener name: per-host rows such as request smuggling, whose defect is in how the server
	// itself parses requests and so cannot be a route on the shared server.
	listeners map[string]*vulnapp.Listener
}

// startRuntimeTarget serves vulnapp, requests every declared endpoint over real HTTP, and stores
// each request/response pair as the scanner would have captured it through the proxy.
// startRuntimeTarget returns the package-shared target; see runtime_shared_test.go for why it is
// shared rather than built per test.
func startRuntimeTarget(t *testing.T) *runtimeTarget {
	t.Helper()
	return sharedRuntimeTarget(t)
}

// buildRuntimeTarget constructs the live corpus target. Called exactly once per test binary.
func buildRuntimeTarget(t *testing.T) *runtimeTarget {
	t.Helper()

	srv := httptest.NewServer(vulnapp.Handler())
	runtimeResetMailbox = srv.URL + vulnapp.PwresetMailboxPath

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse target port: %v", err)
	}

	// A second server over TLS, because several transport rows are gated on the exchange having
	// been encrypted - a cacheable HTTPS response, mixed content, HSTS not enforced. On a
	// cleartext-only harness those can never fire, and that is a property of the fixture rather
	// than of the check: reporting them as undemonstrable would blame the wrong thing.
	// EnableHTTP2 has to be set between NewUnstartedServer and StartTLS - httptest.NewTLSServer does
	// both internally and leaves NextProtos as http/1.1 only, so ALPN could never negotiate h2 and
	// the Hidden HTTP 2 row was unreachable for a reason that had nothing to do with the check.
	tlsSrv := httptest.NewUnstartedServer(vulnapp.Handler())
	tlsSrv.EnableHTTP2 = true
	tlsSrv.StartTLS()
	tlsHost, tlsPortStr, err := net.SplitHostPort(strings.TrimPrefix(tlsSrv.URL, "https://"))
	if err != nil {
		t.Fatalf("split tls target address: %v", err)
	}
	var tlsPort uint16
	if _, err := fmt.Sscanf(tlsPortStr, "%d", &tlsPort); err != nil {
		t.Fatalf("parse tls target port: %v", err)
	}

	rt := &runtimeTarget{
		srv: srv, host: host, port: port,
		tlsSrv: tlsSrv, tlsHost: tlsHost, tlsPort: tlsPort,
		store:     core.NewTrafficStore(),
		exchanges: map[string]core.ExchangeID{},
		listeners: map[string]*vulnapp.Listener{},
	}
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Listener == "" || rt.listeners[e.Listener] != nil {
			continue
		}
		l, err := vulnapp.StartListener(e.Listener)
		if err != nil {
			t.Fatalf("start listener %s for %s: %v", e.Listener, e.Path, err)
		}
		if l.TLS {
			t.Fatalf("listener %s is TLS; the runtime corpus seeds listeners over cleartext only", e.Listener)
		}
		rt.listeners[e.Listener] = l
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		// Redirects must not be followed: the open-redirect endpoint's 302 *is* the evidence,
		// and a client that chased it would store the destination instead.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	tlsClient := tlsSrv.Client()
	tlsClient.Timeout = 10 * time.Second
	tlsClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	for _, e := range vulnapp.Vulnerabilities() {
		if e.TLS {
			rt.seed(t, tlsClient, e)
			continue
		}
		rt.seed(t, client, e)
	}
	if len(rt.exchanges) == 0 {
		t.Fatal("no exchanges were captured from the target; every assertion below would be vacuous")
	}

	// A session coordinator carrying a credential for the target.
	//
	// The access-control and CSRF rows compare an authenticated request against an anonymous one, so
	// without one they can only report a missing capability - honest, but it leaves two rows
	// undemonstrable for a reason belonging to the harness rather than the check. The cookie is
	// absorbed through HandleResponse, the same path a real scan uses to learn a session from a login
	// response, rather than by reaching into the jar.
	coord := session.NewCoordinator(zap.NewNop())
	coord.HandleResponse(host, port, false, http.StatusOK,
		map[string]string{"Set-Cookie": "session=bsy-runtime-session; Path=/"}, nil)

	// Two scanners over one store. Auditing every endpoint with the 48 DOM rows drives a browser
	// for each, which cost ~50s per endpoint and told us nothing about the ten non-DOM rows.
	rt.scan = NewActiveScanner(rt.store, zap.NewNop()).
		WithSender(runtimeSender()).
		WithStoredLedger(NewStoredLedger()).
		WithSessionCoordinator(coord).
		WithConfig(runtimeScanConfig())

	rt.chrome = chromeOnPath()
	if rt.chrome {
		domCfg := runtimeScanConfig()
		domCfg.CheckDOM = true
		// The fragment rows (vulnapp_fragment_xss.go) are decided by rendering a text/plain HTML
		// fragment in the browser, which is the browser confirmation's switch.
		domCfg.CheckXSSBrowserConfirm = true
		// Headless unless BURPSY_DOM_HEADED=1, which is for watching a flow live.
		// The provider is the package-wide shared Chrome — see runtime_shared_test.go.
		rt.domScan = NewActiveScanner(rt.store, zap.NewNop()).
			WithSender(runtimeSender()).
			WithStoredLedger(NewStoredLedger()).
			WithBrowserProvider(sharedBrowserProvider()).
			WithConfig(domCfg)
	}

	// A third scanner for the stored rows. They are separate because enabling CheckStored on the
	// main one would have all ten plant canaries into every endpoint audited, which is a lot of
	// traffic to answer a question about two endpoints - and because these rows are the only ones
	// whose verdict needs the deferred phase.
	storedCfg := runtimeScanConfig()
	storedCfg.CheckStored = true
	storedCfg.PendingDeadline = 2 * time.Second
	rt.storedScan = NewActiveScanner(rt.store, zap.NewNop()).
		WithSender(runtimeSender()).
		WithStoredLedger(NewStoredLedger()).
		WithConfig(storedCfg)

	// A fourth scanner for the stored DOM rows, which need both halves at once: a canary planted
	// over HTTP, and a browser to run the script that fetches it back and uses it. Kept apart from
	// storedScan for the same reason storedScan is kept apart from scan - turning CheckDOM on there
	// would drive a browser over every page of every stored audit to answer a question about six
	// endpoints.
	if rt.chrome {
		storedDomCfg := runtimeScanConfig()
		storedDomCfg.CheckStored = true
		storedDomCfg.CheckDOM = true
		storedDomCfg.PendingDeadline = 5 * time.Second
		rt.storedDomBrowsers = sharedBrowserProvider()
		rt.storedDomScan = NewActiveScanner(rt.store, zap.NewNop()).
			WithSender(runtimeSender()).
			WithStoredLedger(NewStoredLedger()).
			WithBrowserProvider(rt.storedDomBrowsers).
			WithConfig(storedDomCfg)
	}
	return rt
}

// storedDomScanner returns a stored+DOM scanner with a ledger of its own.
//
// One ledger cannot serve two auditors: FinishScan retires a claim as it resolves, so the second
// caller to ask about the same row is told nothing was planted. The detection test and the
// safe-counterpart test both audit these endpoints, and this target is shared across the binary, so
// a single scanner made the outcome depend on which test function ran first. The browser is the
// expensive part and stays shared; the ledger is cheap and must not be.
func (rt *runtimeTarget) storedDomScanner() *ActiveScanner {
	cfg := runtimeScanConfig()
	cfg.CheckStored = true
	cfg.CheckDOM = true
	cfg.PendingDeadline = 5 * time.Second
	return NewActiveScanner(rt.store, zap.NewNop()).
		WithSender(runtimeSender()).
		WithStoredLedger(NewStoredLedger()).
		WithBrowserProvider(rt.storedDomBrowsers).
		WithConfig(cfg)
}

// runtimeSender is the sender every scanner in this harness uses.
//
// TLSVerify is off because the TLS twin is an httptest server with a self-signed certificate. With
// verification on, every probe to it failed the handshake, so the checks all reported send failures,
// the breaker tripped, and the item came back ItemStateFailed with zero checks run — which reads in
// the manifest as "the row did not fire" and blames the check for a certificate the harness itself
// generated. This is a local test target; skipping verification here is not a policy about scanning.
func runtimeSender() *sender.Sender {
	return sender.NewSender(&sender.SenderConfig{Timeout: 30 * time.Second, TLSVerify: false})
}

// scannerFor picks the DOM-enabled scanner only for endpoints whose row is a DOM row.
func (rt *runtimeTarget) scannerFor(dom bool) *ActiveScanner {
	if dom && rt.domScan != nil {
		return rt.domScan
	}
	return rt.scan
}

// storedFindingsFor audits an endpoint and then runs the scan's deferred phase.
//
// A stored row cannot be confirmed by AuditWithin alone: the canary is planted BY that audit, so no
// response it has seen can contain it. FinishScan re-fetches the pages that might render it and asks
// every deferred claim again. Routing these rows through the same call the CLI would make is the
// point - a harness that skipped it would report the stored rows as silent and leave the manifest
// unable to demonstrate a family that does work.
// dom selects the browser-enabled stored scanner, which the "(stored DOM-based)" rows need: their
// evidence is produced by the deferred phase's render pass, not by any HTTP response.
func (rt *runtimeTarget) auditStoredEndpoint(t *testing.T, path string, dom bool) (map[string]*Finding, uint32) {
	t.Helper()
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if dom {
		if rt.storedDomScan == nil {
			t.Fatal("a stored DOM row was audited with no browser-enabled stored scanner; the caller " +
				"must skip these rows when Chrome is absent rather than audit them against nothing")
		}
		// One batched phase for every stored+DOM endpoint; see storedDomBatch.
		rt.storedDomBatch(t)
		out := map[string]*Finding{}
		for name, f := range rt.storedDomByPath[path] {
			out[name] = f
		}
		return out, rt.storedDomSent[path]
	}

	scan := rt.storedScan

	byRow := map[string]*Finding{}
	outcome, findings := scan.AuditWithin(ctx, id, scan.AuditConfig())
	for _, u := range outcome.undeclaredRows {
		t.Errorf("audit of %s: check reported an undeclared row: %s", path, u)
	}
	deferred, completion := scan.FinishScan(ctx, DefaultAuditConfig())
	if completion.RefetchError != "" {
		t.Fatalf("the deferred phase could not re-fetch: %s", completion.RefetchError)
	}
	// No render assertions here: a DOM row returned above, so this path is the non-DOM stored rows,
	// whose evidence comes from the HTTP re-fetch. The render pass is asserted once, in
	// storedDomBatch, where it actually runs.
	for _, f := range append(findings, deferred...) {
		if f != nil {
			byRow[f.Name] = f
		}
	}
	return byRow, outcome.RequestsSent
}

// storedDomBatch runs the stored-DOM deferred phase once for the whole target.
//
// Every stored+DOM endpoint is audited first, which plants that endpoint's canaries and registers
// its deferred claim. Only then does FinishScan run, so the one re-fetch and the one render pass
// serve all of them. Findings are bucketed by the exchange they name.
func (rt *runtimeTarget) storedDomBatch(t *testing.T) {
	t.Helper()
	rt.storedDomOnce.Do(func() {
		rt.storedDomByPath = map[string]map[string]*Finding{}
		rt.storedDomSent = map[string]uint32{}
		if rt.storedDomScan == nil {
			return
		}
		scan := rt.storedDomScanner()

		byID := make(map[core.ExchangeID]string, len(rt.exchanges))
		for path, id := range rt.exchanges {
			byID[id] = path
		}

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()

		// recordMu guards the result maps while the planting audits below run concurrently.
		var recordMu sync.Mutex
		record := func(path string, f *Finding) {
			if f == nil || path == "" {
				return
			}
			recordMu.Lock()
			defer recordMu.Unlock()
			if rt.storedDomByPath[path] == nil {
				rt.storedDomByPath[path] = map[string]*Finding{}
			}
			rt.storedDomByPath[path][f.Name] = f
		}

		// The planting audits run concurrently, bounded the way the parallel subtests are.
		//
		// Run one after the other they were ~150s - most of the scanner package's critical path -
		// and almost all of it is each audit's browser waiting out its page-settle time, not work.
		// They are independent: each audit plants into its own endpoint's history (every
		// stored-DOM case owns a store per half, vulnapp_stored_dom.go), the ledger is
		// mutex-guarded and keys every canary by the exchange that planted it, and attribution
		// below is by that exchange. What must stay ordered is planting before rendering, and it
		// does: FinishScan runs only after every audit has returned.
		const plantConcurrency = 4
		sem := make(chan struct{}, plantConcurrency)
		var wg sync.WaitGroup
		var planted int
		for _, e := range vulnapp.Vulnerabilities() {
			if !e.Stored || !e.DOM {
				continue
			}
			id, ok := rt.exchanges[e.Path]
			if !ok {
				t.Errorf("%s is declared stored+DOM but was never seeded", e.Path)
				continue
			}
			planted++
			e := e
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				outcome, findings := scan.AuditWithin(ctx, id, scan.AuditConfig())
				recordMu.Lock()
				rt.storedDomSent[e.Path] = outcome.RequestsSent
				recordMu.Unlock()
				for _, f := range findings {
					record(e.Path, f)
				}
			}()
		}
		wg.Wait()
		if planted == 0 {
			return
		}

		deferred, completion := scan.FinishScan(ctx, DefaultAuditConfig())
		if completion.RefetchError != "" {
			t.Errorf("the stored-DOM deferred phase could not re-fetch: %s", completion.RefetchError)
			return
		}
		// The render pass IS the evidence for these rows. A pass that did not happen must fail
		// loudly rather than leave every row silent and looking clean.
		if completion.RenderError != "" {
			t.Errorf("the stored-DOM deferred phase could not render any page: %s", completion.RenderError)
			return
		}
		if completion.Render.Rendered == 0 {
			t.Errorf("the stored-DOM deferred phase rendered no page at all (%s), so every row's "+
				"silence would mean nothing was looked at", completion.Render.Summary())
			return
		}
		t.Logf("stored-DOM phase: %d endpoint(s) planted, one deferred phase, %s",
			planted, completion.Render.Summary())

		for _, f := range deferred {
			if f == nil {
				continue
			}
			// Attribute by the exchange the finding names. A deferred finding that names no known
			// exchange is reported rather than spread across endpoints, because guessing which
			// endpoint it belongs to is how a finding ends up describing the wrong one.
			path, ok := byID[f.ExchangeID]
			if !ok {
				t.Errorf("deferred stored-DOM finding %q names exchange %d, which no endpoint owns",
					f.Name, f.ExchangeID)
				continue
			}
			record(path, f)
		}
	})
}

// auditCount reports how many audits have actually run, as opposed to memo hits.
func (rt *runtimeTarget) auditCount() int {
	rt.memoMu.Lock()
	defer rt.memoMu.Unlock()
	return rt.freshAudits
}

// auditOnce memoises one endpoint's audit for the lifetime of a runtimeTarget.
//
// The safe-counterpart test audits a row's VULNERABLE twin once per safe entry, to prove the row is
// live before trusting the safe endpoint's silence. Rows sharing a twin therefore re-audited the same
// endpoint several times over, and for a DOM twin each repeat drives a real browser - the single
// largest avoidable cost in this suite. Memoising is sound because the pairing only requires the twin
// to have fired in THIS run, which a cached result from this run satisfies exactly.
//
// Deliberately keyed including the stored flag: a stored audit plants canaries and mutates the
// ledger, so replaying it is not merely slow, it is a different scan each time.
func (rt *runtimeTarget) auditOnce(t *testing.T, path string, dom, stored bool,
	run func(*testing.T) (map[string]*Finding, uint32)) memoisedAudit {

	t.Helper()
	key := fmt.Sprintf("%s|%v|%v", path, dom, stored)
	rt.memoMu.Lock()
	if rt.memo == nil {
		rt.memo = map[string]*memoisedAudit{}
	}
	if got, ok := rt.memo[key]; ok {
		rt.memoMu.Unlock()
		// Someone else owns this key. Wait for their audit rather than starting a second one.
		<-got.done
		return *got
	}
	// Claim the key before releasing the lock, so a racing caller finds this entry and waits on it
	// instead of racing us.
	entry := &memoisedAudit{done: make(chan struct{})}
	rt.memo[key] = entry
	rt.memoMu.Unlock()

	// The audit itself runs outside the lock: it takes seconds and drives a browser for DOM rows,
	// so holding the mutex across it would serialise every parallel subtest onto the slowest one.
	// Different keys still run concurrently; only a second audit of the SAME key is prevented.
	//
	// This used to let two subtests racing on the same fresh endpoint both audit it, on the
	// reasoning that a duplicate audit was "wasteful once, never wrong". That is not true of a
	// check holding one-shot state per input on the scanner these subtests share. JWT weak HMAC
	// secret is exactly that: JwtWeakSecretCheck.claim (jwt_weak.go) fires once per signing input,
	// so the losing audit of a duplicated pair came back with no JWT finding — and could then win
	// the memo write, leaving the row looking dead. The safe-counterpart guard then correctly
	// refused to accept the twin's silence as evidence, and the suite failed on a race rather than
	// on anything about the scanner.
	//
	// Closing in a defer matters: run() reaches t.Fatalf on failure, which unwinds via
	// runtime.Goexit, and a waiter blocked on this channel would otherwise hang until the timeout.
	defer close(entry.done)

	byRow, sent := run(t)

	rt.memoMu.Lock()
	entry.byRow, entry.requestsSent = byRow, sent
	rt.freshAudits++
	rt.memoMu.Unlock()
	return *entry
}

// memoisedAudit carries the probe count with the findings, so the request-budget test still reads
// the count belonging to the audit it asked for rather than whichever ran most recently.
type memoisedAudit struct {
	byRow        map[string]*Finding
	requestsSent uint32
	// done is closed once this entry's audit has finished. A caller that finds an entry already in
	// the map waits on it rather than running a duplicate audit of the same endpoint; see auditOnce.
	done chan struct{}
}

// findingsFor audits one endpoint, once per target.
func (rt *runtimeTarget) findingsFor(t *testing.T, path string, dom bool) map[string]*Finding {
	t.Helper()
	return rt.auditOnce(t, path, dom, false, func(t *testing.T) (map[string]*Finding, uint32) {
		return rt.auditEndpoint(t, path, dom)
	}).byRow
}

// findingsWithProbeCount returns the audit plus the probes it sent, so the budget test reads the
// count belonging to ITS endpoint rather than a shared field another parallel subtest just wrote.
func (rt *runtimeTarget) findingsWithProbeCount(t *testing.T, path string, dom bool) (map[string]*Finding, uint32) {
	t.Helper()
	entry := rt.auditOnce(t, path, dom, false, func(t *testing.T) (map[string]*Finding, uint32) {
		return rt.auditEndpoint(t, path, dom)
	})
	return entry.byRow, entry.requestsSent
}

// storedFindingsFor audits one endpoint through the deferred phase, once per target.
func (rt *runtimeTarget) storedFindingsFor(t *testing.T, path string, dom bool) map[string]*Finding {
	t.Helper()
	return rt.auditOnce(t, path, dom, true, func(t *testing.T) (map[string]*Finding, uint32) {
		return rt.auditStoredEndpoint(t, path, dom)
	}).byRow
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
	rt.exchanges[e.Path] = rt.capture(t, client, e)
}

// capture sends e's request to the live target and stores the exchange, returning its ID without
// registering it in rt.exchanges: that map is built once and read by parallel tests, so a test that
// needs a fresh capture of its own takes the ID instead of writing to it.
func (rt *runtimeTarget) capture(t *testing.T, client *http.Client, e vulnapp.Endpoint) core.ExchangeID {
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
	baseURL := rt.srv.URL
	if e.TLS {
		baseURL = rt.tlsSrv.URL
	}
	if l := rt.listeners[e.Listener]; l != nil {
		baseURL = l.URL()
	}
	req, err := http.NewRequest(method, baseURL+e.Path, reader)
	if err != nil {
		t.Fatalf("build request for %s: %v", e.Path, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// An Origin is needed for the CORS row to have anything to reflect.
	req.Header.Set("Origin", "https://evil.example")
	// Headers the endpoint declares it must be captured with. A check reading a request header can
	// only find one the seeded request actually sent.
	for k, v := range e.RequestHeaders {
		req.Header.Set(k, v)
	}
	// net/http sends req.Host, never a Host in the header map: an endpoint addressed by a hostname of
	// its own (the subdomain-takeover fixtures) declares it as a Host request header.
	if h, ok := e.RequestHeaders["Host"]; ok {
		req.Host = h
	}

	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("request %s: %v", e.Path, err)
	}
	defer func() { _ = res.Body.Close() }()

	exHost, exPort, exTLS := rt.host, rt.port, false
	if e.TLS {
		exHost, exPort, exTLS = rt.tlsHost, rt.tlsPort, true
	}
	if l := rt.listeners[e.Listener]; l != nil {
		exHost, exPort, exTLS = l.Host, l.Port, l.TLS
	}
	rawReq := buildRawRequest(method, e.Path, exHost, exPort, body, contentType, e.RequestHeaders)
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
		Request: core.MsgPtr(reqID), Response: &respID,
		Host: exHost, Port: exPort, TLS: exTLS,
		Method: method, Path: e.Path,
	}
	rt.store.AddExchange(ex)
	return ex.ID
}

func buildRawRequest(method, path, host string, port uint16, body, contentType string, extra map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	// The endpoint's own Host, when it declares one (the takeover fixtures answer per hostname).
	if _, named := extra["Host"]; !named {
		fmt.Fprintf(&b, "Host: %s\r\n", net.JoinHostPort(host, fmt.Sprint(port)))
	}
	// The default Origin, unless the endpoint declares its own: a WebSocket handshake is captured from
	// the application's own origin, and a second Origin line would make the capture ambiguous.
	ownOrigin := false
	for k := range extra {
		ownOrigin = ownOrigin || strings.EqualFold(k, "Origin")
	}
	if !ownOrigin {
		b.WriteString("Origin: https://evil.example\r\n")
	}
	for k, v := range extra {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
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
	if res.StatusCode == http.StatusSwitchingProtocols {
		// A 101 has no body: what follows is the WebSocket stream, which the proxy records as messages,
		// not as part of the handshake's response.
		return b.String()
	}
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
//   - CheckExtendedActive (22 rows) — of these only the three External-service-interaction rows,
//     the collaborator technique of "Out-of-band resource load (HTTP)" and "TLS certificate" need
//     the network (a collaborator binary, or the tlsx subprocess). That row's in-band technique
//     needs neither and IS on (CheckSSRFInBand). The other ~17 are network-free and SHOULD be enabled here;
//     an earlier version of this comment claimed the whole family needed outbound internet, which
//     was simply wrong.
//   - CheckStored (10 rows) — the manifest declares no stored vulnerability yet, so turning it on
//     would exercise the planting half against endpoints that never surface a canary.
//   - CheckSSRF — subsumed by CheckExtendedActive's gate. CheckXXE admits only the XXE row, which
//     CheckExtendedActive (on here) admits too.
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
		// The active file-upload check (0vzb.15). It only acts on a request carrying a multipart
		// file part, so every other endpoint costs it nothing.
		CheckFileUpload: true,
		// The in-band SSRF technique of the "Out-of-band resource load (HTTP)" row (0vzb.6, j1mk.9).
		// It plants a canary this test process serves on loopback, which the vulnapp SSRF fixtures
		// reach because they share the host; no collaborator is involved.
		CheckSSRFInBand: true,
		// The IDOR check (0vzb.12). It only acts on a credentialed read with an object reference.
		CheckIDOR: true,
		// The login rate-limit and username-enumeration rows (checks_auth_logic.go). They act only on a
		// request carrying an identity and a password or one-time-code field, and the rate-limit burst
		// stops after one request unless the answer shows the endpoint evaluates credentials.
		CheckLoginRateLimit:      true,
		CheckUsernameEnumeration: true,
		// The heavy-query time-delay families of the SQL row (v0ei.1): the SQLite, DB2, H2, HSQLDB
		// and filtered-MySQL dialect endpoints are reachable only through them.
		CheckSqliHeavyQuery: true,
		// The widening `or` boolean shapes of the SQL row (v0ei.4): the members lookup whose seeded
		// value matches nobody is reachable only through them.
		CheckSqliOrBoolean: true,
		// The password-reset checks. They act only on a reset request for one of vulnapp's own test
		// identities, and read the tokens from vulnapp's in-memory test inbox.
		CheckPasswordReset:  true,
		ResetTestIdentities: vulnapp.PwresetIdentities(),
		ResetMailboxURL:     runtimeResetMailbox,
		// The session-management check (0vzb wave 5). It only acts on a captured login that set a cookie.
		CheckSessionManagement: true,
		// The Host header check (checks_host_header.go). It sends canary hosts under .invalid to the
		// loopback target only; the scope gate never reads the Host header.
		CheckHostHeader: true,
		// The GraphQL hardening rows (checks_graphql_hardening.go). They act only on a URL whose answer to
		// an aliased __typename query proves it executes GraphQL.
		CheckGraphQLHardening: true,
		// Insecure deserialization (0vzb.10): benign accepted/rejected pairs in recognised serialized
		// values and opaque cookies; it touches only the /deser fixtures' kind of request.
		CheckInsecureDeserialization: true,
		// The NoSQL injection check (v0ei.6). It acts only on reads and logins with a query, form or
		// JSON value.
		CheckNoSQLInjection: true,
		// Server-side parameter pollution (0vzb.3): delimiters appended to query and body values of GET
		// and POST requests, each against its literal control; the internal APIs are vulnapp's own.
		CheckServerSideParamPollution: true,
		// LLM prompt injection (0vzb.18): a benign canary-transform instruction appended to text values of
		// requests a model likely answers; the stand-in models are vulnapp's own.
		CheckLLMPromptInjection: true,
		// Weak cryptography (0vzb.28): random markers in query and body values, their computed digests
		// and ECB block repetition looked for in the answer; the hashing and login endpoints are vulnapp's.
		CheckWeakCrypto: true,
		// JWT credential exposure (0vzb.29): the captured request replayed with the token's signature
		// altered and with the token removed, to show the exposed JWT is a verified credential.
		CheckJwtExposure: true,
		// Cross-site WebSocket hijacking and the client-IP header checks (vulnapp_wsip.go). The first acts
		// only on a captured cookie-authenticated handshake; the second puts loopback and documentation
		// (203.0.113.0/24) addresses in client-IP headers, sent to the loopback target only.
		CheckWebSocketHijacking: true,
		CheckClientIPSpoofing:   true,
		// The cookie prefix / SameSite rows and subdomain takeover (0vzb.19, 0vzb.17): passive. The
		// takeover check asks vulnapp's fake DNS, never a real resolver.
		CheckCookieAttributes:  true,
		CheckSubdomainTakeover: true,
		DNSResolver:            vulnapp.NewTakeoverResolver(),
	}
}

// runtimeResetMailbox is vulnapp's test inbox on the cleartext target, set by buildRuntimeTarget
// before any scanner is configured (the TLS twin shares the same in-memory inbox).
var runtimeResetMailbox string

// findingsFor audits one seeded endpoint with the real engine and returns the row names reported.
// dom selects the browser-enabled scanner, so non-DOM endpoints never pay for a page load.
func (rt *runtimeTarget) auditEndpoint(t *testing.T, path string, dom bool) (map[string]*Finding, uint32) {
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
	// A check that reports a row it does not declare could never be admitted by only_rows naming that
	// row (only_rows.go). The fix is alsoReports, or a rider in BurpsyNativeRows.
	for _, u := range outcome.undeclaredRows {
		t.Errorf("audit of %s: check reported an undeclared row: %s", path, u)
	}
	byRow := make(map[string]*Finding, len(findings))
	for _, f := range findings {
		if f != nil {
			byRow[f.Name] = f
		}
	}
	return byRow, outcome.RequestsSent
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
	var mu sync.Mutex

	// Grouped so the accounting below runs after every parallel subtest has finished.
	t.Run("endpoints", func(t *testing.T) {
		for _, e := range vulnapp.Vulnerabilities() {
			if e.Row == "" {
				continue
			}
			e := e
			t.Run(e.Path, func(t *testing.T) {
				// The stored rows of vulnapp_stored.go stay serial: their submissions land in
				// histories that render pages audited in parallel below go on to serve, so the
				// plants have to be finished before those audits start.
				//
				// The stored DOM-based endpoints do not have that coupling, and were ~130s of
				// serial wall clock here (26 browser-driven audits of ~5s each, one after the
				// other). This test audits them through the ordinary scanner - CheckStored is
				// off, so nothing reaches a ledger - and each one appends only to its own
				// case's history (vulnapp_stored_dom.go gives every endpoint a store of its
				// own). The render pages that read those histories declare no row, so no audit
				// in this test reads them; the only reader is the stored-DOM deferred phase,
				// which runs in a later test function, after this one has returned.
				if !e.Stored || e.DOM {
					t.Parallel()
				}
				_, sent := rt.findingsWithProbeCount(t, e.Path, e.DOM)
				mu.Lock()
				audited++
				total += sent
				mu.Unlock()

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
	})
	if audited == 0 {
		t.Fatal("no endpoint was audited")
	}
	t.Logf("request accounting: %d probes across %d endpoints (mean %d)", total, audited, total/uint32(audited))
}

// The headline assertion: every vulnerability vulnapp declares must actually be reported.
func TestTheScannerDetectsWhatTheTargetDeclaresItIsVulnerableTo(t *testing.T) {
	rt := startRuntimeTarget(t)
	// Snapshot, not absolute: freshAudits accumulates over the whole binary, so comparing it to zero
	// would only ever be true on the very first test to run. The delta is what says whether THIS
	// invocation measured anything.
	auditsBefore := rt.auditCount()

	// A row name that does not exist in the catalog would exempt its endpoint from every
	// assertion here, so the manifest is resolved before anything is audited.
	catalog := map[string]bool{}
	for _, d := range NativeCheckRegistry() {
		catalog[d.Name] = true
	}
	// burpsy's own rows (burpsy_rows.go) are reported by checks riding a Burp descriptor.
	for _, r := range BurpsyNativeRows() {
		catalog[r.Name] = true
	}
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row != "" && !catalog[e.Row] {
			t.Fatalf("vulnapp declares %q for %s, which is not a catalog row name; the assertion would never run",
				e.Row, e.Path)
		}
	}

	var demonstrated, missed, skipped []string
	// The rows run inside a group so the tally below sees their results.
	//
	// A parallel subtest is deferred until its parent returns, so counting demonstrated rows straight
	// after the loop would read empty slices and the coverage floor would fire on a green run. The
	// group blocks until every child finishes, which is what makes the two safe to combine.
	var tally sync.Mutex
	t.Run("rows", func(t *testing.T) {
		for _, e := range vulnapp.Vulnerabilities() {
			if e.Row == "" || e.Safe {
				continue
			}
			e := e
			t.Run(e.Row+" via "+e.Path, func(t *testing.T) {
				// Stored rows stay serial: they plant into a scan-wide ledger, so running two at once
				// makes the second one's evidence depend on the first one's timing. Every other row
				// audits an independent endpoint, and results are memoised, so parallel subtests
				// overlap only on wall clock rather than on state.
				if !e.Stored {
					t.Parallel()
				}
				if e.DOM && !rt.chrome {
					tally.Lock()
					skipped = append(skipped, e.Row+" @ "+e.Path)
					tally.Unlock()
					t.Skip("no Chrome on PATH: this DOM row is NOT exercised in this run")
				}
				var got map[string]*Finding
				if e.Stored {
					got = rt.storedFindingsFor(t, e.Path, e.DOM)
				} else {
					got = rt.findingsFor(t, e.Path, e.DOM)
				}
				tally.Lock()
				defer tally.Unlock()
				if _, fired := got[e.Row]; !fired {
					missed = append(missed, e.Row+" @ "+e.Path)
					t.Errorf("the target is vulnerable here (%s) but %q was not reported.\nrows reported instead: %s",
						e.Note, e.Row, joinRows(got))
					return
				}
				demonstrated = append(demonstrated, e.Row)
			})
		}
	})

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
	// A replay served entirely from the memo must not print the claim as though it measured it.
	//
	// `-count=2` is the standard way to shake out flakes, and the shared target outlives a single
	// iteration, so the second pass completed in 10ms from cache and printed a coverage line
	// identical to the first. An operator would reasonably read two matching numbers as
	// reproduction. It was a cache read.
	if fresh := rt.auditCount() - auditsBefore; fresh == 0 && len(demonstrated) > 0 {
		t.Logf("cached replay: %d row(s) served from a previous iteration's audits, no probe was sent "+
			"and no coverage claim was re-verified in this pass", len(distinct))
		return
	}
	t.Logf("runtime detection: %d distinct catalog rows demonstrated across %d endpoints, %d missed",
		len(distinct), len(demonstrated), len(missed))

	var claimed int
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row != "" && !e.Safe {
			claimed++
		}
	}
	const wantDemonstrated = 188

	// Chrome is a required dependency of this suite, so its absence is a broken machine rather than
	// a supported mode - and this is where that gets enforced.
	//
	// A row skipped for a missing capability and a row filtered out by `-run` look identical to a
	// tally: both are simply absent. The earlier version returned early for either, which left the
	// coverage pin unenforced with only a t.Logf to say so, so a machine without Chrome exited 0
	// having demonstrated 116 rows against a pinned claim of 145. That is "we did not look" reading
	// as "we looked and found nothing", which is the one outcome this project's standard forbids.
	// Found in review.
	//
	// Failing is the right behaviour precisely BECAUSE Chrome is a base dependency: a misconfigured
	// environment should say which dependency is missing, not quietly verify less than it claims.
	// BURPSY_ALLOW_UNVERIFIED_COVERAGE=1 exists for a deliberately reduced environment and is loud
	// about what it cost.
	if len(skipped) > 0 {
		distinctSkipped := map[string]bool{}
		for _, r := range skipped {
			distinctSkipped[r] = true
		}
		msg := fmt.Sprintf("%d row(s) were skipped for a missing capability, so this run cannot "+
			"verify the pinned coverage claim of %d rows; it demonstrated %d. Skipped: %v",
			len(distinctSkipped), wantDemonstrated, len(distinct), skipped)
		if os.Getenv("BURPSY_ALLOW_UNVERIFIED_COVERAGE") == "1" {
			t.Logf("COVERAGE UNVERIFIED (allowed by BURPSY_ALLOW_UNVERIFIED_COVERAGE): %s", msg)
			return
		}
		t.Fatalf("%s\nInstall Chrome to exercise them, or set BURPSY_ALLOW_UNVERIFIED_COVERAGE=1 to "+
			"accept a run that does not check the claim.", msg)
	}

	// Now the only remaining reason for an incomplete tally is a `-run` filter, where a pin would
	// fail every filtered debugging run for a reason unrelated to what is being debugged.
	if len(demonstrated)+len(missed) < claimed {
		t.Logf("filtered run (%d of %d endpoints attempted): coverage floor not enforced",
			len(demonstrated)+len(missed), claimed)
		return
	}
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

	// Row -> a vulnerable endpoint for it, so each safe case can prove the row is live. The stored
	// flag travels with it: a stored row's verdict only exists after the deferred phase, so both
	// halves of the pairing have to go through the same path the detection test uses. Auditing the
	// vulnerable twin without it would report "did not fire against its twin" for every stored row
	// and make a genuine safe twin impossible to express.
	type twin struct {
		path   string
		stored bool
		dom    bool
	}
	vulnerableTwin := map[string]twin{}
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row != "" && !e.Safe {
			if _, seen := vulnerableTwin[e.Row]; !seen {
				vulnerableTwin[e.Row] = twin{path: e.Path, stored: e.Stored, dom: e.DOM}
			}
		}
	}

	// findings picks the path a row's verdict actually comes from.
	findings := func(t *testing.T, path string, dom, stored bool) map[string]*Finding {
		if stored {
			return rt.storedFindingsFor(t, path, dom)
		}
		return rt.findingsFor(t, path, dom)
	}

	var checked int
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row == "" || !e.Safe {
			continue
		}
		checked++
		e := e
		t.Run(e.Row+" via "+e.Path, func(t *testing.T) {
			// Same rule as the detection half: everything but the stored rows is independent.
			if !e.Stored && !vulnerableTwin[e.Row].stored {
				t.Parallel()
			}
			if e.DOM && !rt.chrome {
				t.Skip("no Chrome on PATH: this DOM row is NOT exercised in this run")
			}
			tw, ok := vulnerableTwin[e.Row]
			if !ok {
				t.Fatalf("no vulnerable endpoint declared for %q, so silence here proves nothing", e.Row)
			}
			if fired := findings(t, tw.path, tw.dom, tw.stored); fired[e.Row] == nil {
				t.Fatalf("%q did not fire against its vulnerable twin %s in this run, so its silence "+
					"on %s is not evidence of anything — the check may simply not be working here",
					e.Row, tw.path, e.Path)
			}

			got := findings(t, e.Path, e.DOM, e.Stored)
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
	//
	// The reason is read from the manifest rather than kept in a table here. A second source of
	// truth would let a row be exempted in one file and required in the other, and the exemption
	// belongs next to the endpoint claiming it, where a reviewer of that endpoint will see it.
	noSafeTwin := map[string]string{}
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row != "" && !e.Safe && strings.TrimSpace(e.SafeTwinNotApplicable) != "" {
			noSafeTwin[e.Row] = e.SafeTwinNotApplicable
		}
	}

	for row, paths := range vulnerable {
		if safe[row] {
			continue
		}
		if _, ok := noSafeTwin[row]; ok {
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
