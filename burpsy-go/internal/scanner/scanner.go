package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// ActiveScanner performs active security scanning.
type ActiveScanner struct {
	store  *core.TrafficStore
	logger *zap.Logger
	config *ScanConfig
	sender *sender.Sender
	// scope is the engagement scope, enforced before an item is planned and again on every probe's
	// own bytes. Nil means no caller supplied one — see WithScope.
	scope *core.Scope
	// auditCfg is the budget/breaker configuration, when an operator set one explicitly. Nil defers
	// to AuditConfig, which derives it from ScanConfig.
	auditCfg *AuditConfig
	// corpus holds the loaded BCheck corpus's active checks (given host/path/request/insertion
	// point), dispatched by the audit engine exactly like the built-in table entries. Nil until
	// WithCorpusChecks supplies one — a process without --bchecks audits the built-ins only, so
	// old behaviour is preserved.
	corpus []*bcheck.Check
	// toolRunner executes the `run tool` statements of corpus checks, through
	// the operator's allowlist. Nil means tool execution is disabled: checks
	// that need a tool are counted at load (LoadReport.Tools) and excluded
	// from the dispatch set, never run against nothing.
	toolRunner bcheck.ToolRunner
	// browsers hands out the shared headless browser for DOM checks. Nil means no DOM
	// capability: CheckContext.Browser then returns an error, so a DOM check reports that
	// it could not look rather than reporting an empty observation set.
	browsers BrowserProvider
	// stored is the scan-wide stored-input ledger for the second-order rows. Nil means no
	// stored tracking, and CheckContext.StoredLedger says so rather than returning an
	// empty ledger that would make every stored check look clean.
	stored *StoredLedger
	// domObs caches taint observations per (exchange, source) for one scan. Sixteen DOM families
	// across two variants each asked for the same page with the same sources and then filtered the
	// shared result by sink — roughly eighty browser tabs per exchange to learn one thing five
	// times. Observe once, match many.
	domObs   map[string][]domexec.Observation
	domObsMu sync.Mutex
	// pending carries claims that cannot be settled while the check that made them runs: a
	// planted canary, a callback domain. Created on first use so a scan that defers nothing
	// allocates nothing.
	pending   *PendingRegistry
	pendingMu sync.Mutex
	// sessions is the coordinator the access-control and CSRF rows need. Nil means those
	// checks report a missing capability instead of comparing two anonymous requests.
	sessions *session.Coordinator
	// provenance counts findings by source for the four "<x> generated issue" rows.
	provenance *ProvenanceLedger
	// jsLib and jwtWeak are the two native checks (SCAN-01 in js_vulns.go, SCAN-02 in jwt_weak.go).
	// Each carries its own dataset and coverage counters, so they are built once per scanner and
	// reused across audits rather than rebuilt per exchange — re-parsing the 514 KB retire.js corpus
	// for every audited exchange would dominate the scan. nativeChecks fills them lazily; the two
	// With… setters override before first use.
	jsLib      *JsLibraryCheck
	jwtWeak    *JwtWeakSecretCheck
	nativeOnce sync.Once
	findings   []*Finding
	findingsMu sync.RWMutex
}

// ScanConfig holds scanner configuration: which checks are in the set, and how the session is
// paced.
//
// It is deliberately not merged with AuditConfig, which answers a different question — how much
// work may be admitted before the engine stops. The two share no field, so they cannot disagree.
// Timeout is the one that could have: it is read by ActiveScanner.AuditConfig as the source of the
// audit's wall-clock budget rather than being duplicated there.
type ScanConfig struct {
	MaxConcurrency int
	Timeout        time.Duration
	// ProbeTimeout caps a single active probe (one Send through the authorised
	// sender). Zero inherits the audit item's deadline, so a probe rides the
	// audit's cancellation without its own clock. A positive value derives a
	// child context with its own deadline, so one slow probe is cancelled on its
	// own clock rather than hanging the whole audit.
	ProbeTimeout       time.Duration
	CheckSqli          bool
	CheckXss           bool
	CheckPathTraversal bool
	// CheckSSRF is the SSRF family switch. Its single catalog row, "Out-of-band resource
	// load (HTTP)", now has an evaluator that needs a collaborator binary and outbound DNS,
	// so it is additionally gated behind CheckExtendedActive: enabling CheckSSRF alone no
	// longer admits it. That keeps a default scan from failing every sweep on a machine with
	// no interactsh installed.
	CheckSSRF    bool
	CheckXXE     bool
	CheckJwtWeak bool
	CheckJSVulns bool
	// CheckHeaders admits the CORS/CSP/duplicate-cookie native checks (checks_headers.go).
	CheckHeaders bool
	// CheckCachePoisoning admits the cache poisoning/deception native checks, and the
	// explicitly declined request-smuggling/client-side-desync entries in the same family
	// (checks_cache.go).
	CheckCachePoisoning bool
	// CheckCorpus admits the loaded BCheck corpus's active checks into the audit set. Set by
	// WithCorpusChecks when a corpus is loaded; WithConfig can switch it off. Off with a corpus
	// loaded audits the built-ins alone, which is the honest opt-out.
	CheckCorpus bool
	// CheckExtendedCoverage admits every remaining catalog TypeIndex the registry declares — the
	// Task 6 completeness sweep's native (header/CORS/CSP, cache poisoning/deception) and explicit
	// declined rows. Off by default: these rows have no individual ScanConfig switch of their own
	// (Java gives most of them no equivalent toggle either), so admitting all ~176 of them
	// unconditionally would make every audit report on issues the operator never asked about and
	// would silently change what "the checks I enabled" means for every existing caller. On, an
	// audit gets full 183-TypeIndex accounting: every catalog issue as runnable, tool-dependent or
	CheckExtendedCoverage bool
	// CheckReflectionProbes admits the six single-probe reflection/redirect/injection checks in
	// checks_reflection2.go: input reflection, open redirection, link manipulation, HTTP response
	// header injection, unidentified code injection, and SSI injection. These are the six catalog
	// issues java_check_inventory.json's runtime trace confirmed firing on a live Burp Pro scan
	// (Zr02/Zuag/Zb_5/Zwi/Zsn3/Zexx) that were not yet native. Off by default like every other
	// per-family switch.
	CheckReflectionProbes bool
	// CheckHostDiscovery admits the three host-wide passive-discovery checks in
	// checks_discovery.go: OpenAPI/Swagger definition found, robots.txt file, and GraphQL
	// endpoint discovered. Off by default like every other per-family switch.
	CheckHostDiscovery bool
	// CheckResponseDependence admits the five checks in checks_reflection3.go: backup file
	// discovery, User-Agent-dependent response, Referer-dependent response, ASP.NET debugging
	// enabled, and ASP.NET tracing enabled. Off by default like every other per-family switch.
	CheckResponseDependence bool
	// CheckPassivePosture admits the fifteen network-free passive checks in
	// checks_passive_posture.go: the password-handling family, cross-domain POST,
	// content-type declaration, long redirects, request-URL override, cross-domain Referer
	// leakage, and the transport posture set (cleartext, HSTS, cacheable HTTPS, mixed
	// content). Off by default like every other per-family switch.
	CheckPassivePosture bool
	// CheckPassiveAnalysis admits the twenty-eight network-free analyser checks in
	// checks_passive_analysis.go: cookie security, response/header attributes, the nine
	// information-disclosure families, ASP.NET ViewState, serialized-object recognition,
	// and the five CSP directive rows. Off by default like every other per-family switch.
	CheckPassiveAnalysis bool
	// CheckActiveInjection admits the twelve active injection checks in checks_injection.go:
	// OS command, LDAP, XPath, XML, file path manipulation, server-side template, expression
	// language, and the five interpreted-language code-injection rows. These SEND crafted
	// payloads, so unlike the passive families they are not admissible in a passive-only
	// scan. Off by default like every other per-family switch.
	CheckActiveInjection bool
	// CheckDOM admits the wired DOM-based checks in checks_dom.go. They drive a real headless
	// browser, so they need a browser provider; without one they report a refusal rather than
	// an empty observation set. Off by default like every other per-family switch.
	CheckDOM bool
	// CheckExtendedActive admits the remaining wired rows in checks_remaining.go and
	// checks_final.go: GraphQL, JWT forgery, SMTP header injection, CORS, cross-domain policy
	// files, XXE and entity expansion, file-upload and OpenAPI discovery, React2Shell
	// fingerprinting, the SQL-in-parameter heuristic, and the final sixteen. Off by default.
	CheckExtendedActive bool
	// CheckOutOfBand narrows CheckExtendedActive to also admit the five rows that cannot reach
	// a verdict without something outside this process: the four collaborator rows (out-of-band
	// resource load, and external service interaction over DNS/HTTP/SMTP) and TLS certificate,
	// which shells out to tlsx.
	//
	// It exists because those five behave nothing like their family. Each collaborator row waits
	// five seconds for a callback that cannot arrive on a host with no outbound DNS, so the four
	// of them cost twenty seconds per endpoint whether or not anything is listening - enough to
	// spend a whole scan's time budget and make later checks go silent for want of clock rather
	// than want of evidence. Enabling this alone admits nothing; it only widens the family.
	CheckOutOfBand bool
	// PendingDeadline bounds how long a deferred claim is carried before it is reported
	// outstanding. Zero means DefaultPendingDeadline. Worth setting low in tests and high against
	// a target that queues work rather than acting inline.
	PendingDeadline time.Duration
	// CheckStored admits the stored (second-order) checks in checks_stored.go. They plant
	// canaries into endpoints they audit and can only confirm a finding once one surfaces in a
	// later exchange, so they need a StoredLedger. Off by default.
	CheckStored    bool
	CustomPayloads []string
}

// Finding represents a security finding.
type Finding struct {
	ID          uint64
	Name        string
	Severity    string // "info", "low", "medium", "high", "critical"
	Confidence  string // "certain", "firm", "tentative"
	Description string
	URL         string
	Method      string
	Param       string
	Evidence    string
	Solution    string
	ExchangeID  core.ExchangeID
	Timestamp   time.Time
}

// NewActiveScanner creates a new active scanner.
func NewActiveScanner(store *core.TrafficStore, logger *zap.Logger) *ActiveScanner {
	return &ActiveScanner{
		store:  store,
		logger: logger,
		config: &ScanConfig{
			MaxConcurrency:     10,
			Timeout:            30 * time.Second,
			CheckSqli:          true,
			CheckXss:           true,
			CheckPathTraversal: true,
			CheckSSRF:          true,
			CheckXXE:           false,
		},
		findings: make([]*Finding, 0),
	}
}

// WithConfig sets the scan configuration.
func (s *ActiveScanner) WithConfig(config *ScanConfig) *ActiveScanner {
	s.config = config
	return s
}

// WithSender sets the HTTP sender used to dispatch test requests.
// Without a sender, checks fall back to inspecting the stored exchange response.
func (s *ActiveScanner) WithSender(snd *sender.Sender) *ActiveScanner {
	s.sender = snd
	return s
}

// WithToolRunner attaches the allowlist runner `run tool` statements dispatch
// through. Without one, corpus checks that need a tool are counted at load and
// excluded from the dispatch set — see corpusActiveChecks. Attaching a runner
// after WithCorpusChecks is fine: the gate is read when the dispatch set is
// built, not when the corpus was loaded.
func (s *ActiveScanner) WithToolRunner(r bcheck.ToolRunner) *ActiveScanner {
	s.toolRunner = r
	return s
}

// WithCorpusChecks supplies the loaded BCheck corpus's active checks (given host/path/request/
// insertion point) for the audit engine to dispatch alongside the built-in table. Loading a
// corpus switches its active checks on (ScanConfig.CheckCorpus); WithConfig can turn the switch
// back off. A nil or empty slice leaves the built-in set alone — including the switch, so a
// process with no corpus does not quietly turn a knob that gates nothing.
//
// The checks come from the same LoadDir that built the passive scanner — the audit engine and
// the passive scanner must never disagree about which corpus is loaded.
func (s *ActiveScanner) WithCorpusChecks(checks []*bcheck.Check) *ActiveScanner {
	s.corpus = checks
	if s.config != nil && len(checks) > 0 {
		s.config.CheckCorpus = true
	}
	return s
}

// Audit runs an active audit on an exchange, under this scanner's AuditConfig.
//
// The check set no longer runs as a straight line of ifs: every check passes the audit engine's
// admission gate first, and every check that is not dispatched lands in a named Disposition on the
// outcome. Callers that need to know what was *not* looked at should use AuditWithin, which returns
// that outcome; this signature is kept for the web and CLI call sites that predate it.
//
// An item the engine refused before any dispatch — out of scope, or nothing auditable — comes back
// as an error rather than an empty finding list. With two return values there is no other way to
// keep "audited, found nothing" and "never looked" apart, and collapsing them is the exact defect
// the engine exists to prevent.
func (s *ActiveScanner) Audit(ctx context.Context, exchangeID core.ExchangeID) ([]*Finding, error) {
	outcome, findings := s.AuditWithin(ctx, exchangeID, s.AuditConfig())
	if outcome.Error != "" {
		return nil, errors.New(outcome.Error)
	}
	return findings, nil
}

// AuditMultiple runs audits on multiple exchanges concurrently, under one shared budget, ledger and
// set of circuit breakers.
//
// A thin wrapper over AuditSession, kept at its original signature. AuditSession is the one to call
// for the session outcome: the dispatch-unit count, the checks that were never admitted, and
// whether the failure breaker paused the run.
func (s *ActiveScanner) AuditMultiple(ctx context.Context, exchangeIDs []core.ExchangeID) ([]*Finding, error) {
	outcome, findings := s.AuditSession(ctx, exchangeIDs, s.AuditConfig())
	// The outcome now carries every refusal with its reason, but the log line stays: a caller that
	// only reads stderr must not lose the fact that an exchange was skipped.
	if s.logger != nil {
		for _, item := range outcome.Items {
			if item.Outcome.Error != "" {
				s.logger.Warn("audit skipped",
					zap.Uint64("exchange_id", uint64(item.ExchangeID)),
					zap.String("reason", item.Outcome.Error))
			}
		}
	}
	if findings == nil {
		findings = make([]*Finding, 0)
	}
	return findings, nil
}

// noEngagementScope is the gate a scanner built without WithScope uses.
//
// It authorises everything, which is what ActiveScanner has always done with a nil scope — see
// WithScope: nil means "no scope was supplied", not "nothing is in scope". It exists so that the
// nil case does not get its own egress path. There is exactly one place a probe leaves this
// process, and it is always through an AuthorisedSender; a second branch calling Sender.Send
// directly is how a chokepoint stops being unbypassable, which is the whole of HARD-03.
type noEngagementScope struct{}

func (noEngagementScope) AuthoriseRaw(string, uint16, bool, []byte) error { return nil }

// probeGate binds the engagement scope and this scanner's sender to one exchange's authority, so
// every probe at it is authorised against the bytes it will actually put on the wire.
func (s *ActiveScanner) probeGate(exchange *core.Exchange) *sender.AuthorisedSender {
	var gate sender.ScopeChecker = noEngagementScope{}
	if s.scope != nil {
		gate = s.scope
	}
	return sender.NewAuthorisedSender(gate, s.sender, exchange.Host, exchange.Port, exchange.TLS)
}

// sendTestRequest dispatches a crafted test request through the sender when
// available, otherwise falls back to the stored response body of the original
// exchange (offline audit).
//
// Every probe that leaves this process leaves from here, which makes it the only place the audit
// engine needs to instrument. It does two things beyond sending:
//
//   - It meters the probe. The meter rides on ctx (see meterKey) and is both what the request budget
//     bounds and what tells a check that ran from a check that never saw its own probe response.
//   - It authorises the probe against the engagement scope, through the same shared chokepoint every
//     other request-originating surface uses: sender.AuthorisedSender.SendRequest, which runs
//     core.Scope.AuthoriseRaw over the rendered request line before the dial.
//
// # Why the bytes and not testURL
//
// This used to call scope.AuthoriseRequest(host, port, testURL, tls) and then Sender.Send, which
// authorises nothing. That was a real check, not a bypass, but it was a weaker one and it asked the
// wrong question. Scope is defined over request *paths* — core.Scope's requestPath drops the query
// string, exactly as burpsy-core does — and testURL is a path with a query string glued to it. So the
// string handed to a parameter meaning "path" was one no request line ever carries, and the two
// checks could disagree in both directions:
//
//   - Over-refusal, today's shape. Every check here splices its payload into the query, so an
//     operator rule written as exclude(host, "/search?") matched the glued string and refused probes
//     whose request line — GET /search?… — is squarely in scope. No rule of that shape can ever match
//     a real path, so the refusals were an artefact of the gluing.
//   - Under-refusal, as soon as a payload reaches a path position. The wire path is not a prefix of
//     testURL in general: url.Parse plus RequestURI re-encodes bytes a path may not carry literally
//     and turns an empty path into "/", so an exclude the operator wrote can match the request line
//     while missing the string this check read. A probe would then leave under a rule that forbids it.
//
// AuthoriseRaw closes both because it reads the rendered request line, and sender.Render and
// sender.Send derive that line and the dialled URL from one parse — so the gate cannot be authorising
// a target the wire does not carry.
//
// # Why Refused() and not the error text
//
// SendRequest refuses on scope, on a wrong authority and on a request it cannot even render, and
// fails separately at the transport. Its refusal counter is the exact discriminator between "nothing
// left this process" and "the target did not answer", so the meter reads that rather than matching on
// an error string. One consequence is deliberate: a probe whose testURL will not parse is now a
// refusal rather than a send failure. Nothing was sent and the target did not misbehave, so counting
// it against the target — and against the failure breaker that abandons units — would blame the host
// for our own malformed probe. probeMeter.refusal already also increments the failure count, so the
// breakers see the same thing either way.
//
// A refused probe returns nothing rather than the stored response: the fallback exists so an
// operator with no sender can still audit captured traffic, not so a check can derive a verdict
// about a payload that was never authorised to leave.
func (s *ActiveScanner) sendTestRequest(ctx context.Context, exchange *core.Exchange, testURL string) string {
	if s.sender != nil {
		meter := meterFrom(ctx)
		meter.attempt()
		gate := s.probeGate(exchange)
		resp, err := gate.SendRequest(ctx, &sender.Request{
			Method: exchange.Method,
			Host:   exchange.Host,
			Path:   testURL,
			TLS:    exchange.TLS,
			Port:   exchange.Port,
		})
		if gate.Refused() > 0 {
			meter.refusal()
			if s.logger != nil {
				s.logger.Warn("test request refused: outside the engagement scope",
					zap.String("host", exchange.Host), zap.String("url", testURL), zap.Error(err))
			}
			return ""
		}
		if err == nil && resp != nil {
			meter.succeeded()
			return string(resp.Body)
		}
		meter.failure()
		if s.logger != nil {
			s.logger.Warn("test request failed, falling back to stored response",
				zap.String("host", exchange.Host), zap.String("url", testURL), zap.Error(err))
		}
	}
	return s.getResponseBody(exchange)
}

// sendTestRequestFull is sendTestRequest's sibling for checks that need the response status line
// and headers, not only the body — open redirection needs the Location header, and HTTP response
// header injection needs to see whether an injected header actually landed. There is no stored-
// response fallback here (unlike sendTestRequest): a captured exchange has no equivalent full
// sender.Response for a probe that was never sent, so an unavailable or refused sender returns nil
// rather than a fabricated one. headers overrides/adds request headers for probes that inject
// through User-Agent/Referer rather than the query string (Zsn3/Zexx's real insertion points per
// out/strings/map_root.tsv); nil sends the request with only its normal headers.
func (s *ActiveScanner) sendTestRequestFull(ctx context.Context, exchange *core.Exchange, testURL string, headers map[string]string) *sender.Response {
	if s.sender == nil {
		return nil
	}
	meter := meterFrom(ctx)
	meter.attempt()
	gate := s.probeGate(exchange)
	resp, err := gate.SendRequest(ctx, &sender.Request{
		Method:  exchange.Method,
		Host:    exchange.Host,
		Path:    testURL,
		Headers: headers,
		TLS:     exchange.TLS,
		Port:    exchange.Port,
	})
	if gate.Refused() > 0 {
		meter.refusal()
		if s.logger != nil {
			s.logger.Warn("test request refused: outside the engagement scope",
				zap.String("host", exchange.Host), zap.String("url", testURL), zap.Error(err))
		}
		return nil
	}
	if err == nil && resp != nil {
		meter.succeeded()
		return resp
	}
	meter.failure()
	if s.logger != nil {
		s.logger.Warn("test request failed", zap.String("host", exchange.Host), zap.String("url", testURL), zap.Error(err))
	}
	return nil
}

// sendTestRequestBody is sendTestRequestFull's sibling for probes that need a specific method and
// body rather than the exchange's own method and an empty body — GraphQL endpoint discovery POSTs
// a JSON query body to a candidate path that has nothing to do with the captured exchange's own
// request. Same refusal/failure semantics as sendTestRequestFull: no sender or a refused/failed
// probe returns nil, never a fabricated response.
func (s *ActiveScanner) sendTestRequestBody(ctx context.Context, exchange *core.Exchange, method, path string, headers map[string]string, body []byte) *sender.Response {
	if s.sender == nil {
		return nil
	}
	meter := meterFrom(ctx)
	meter.attempt()
	gate := s.probeGate(exchange)
	resp, err := gate.SendRequest(ctx, &sender.Request{
		Method:  method,
		Host:    exchange.Host,
		Path:    path,
		Headers: headers,
		Body:    body,
		TLS:     exchange.TLS,
		Port:    exchange.Port,
	})
	if gate.Refused() > 0 {
		meter.refusal()
		if s.logger != nil {
			s.logger.Warn("test request refused: outside the engagement scope",
				zap.String("host", exchange.Host), zap.String("url", path), zap.Error(err))
		}
		return nil
	}
	if err == nil && resp != nil {
		meter.succeeded()
		return resp
	}
	meter.failure()
	if s.logger != nil {
		s.logger.Warn("test request failed", zap.String("host", exchange.Host), zap.String("url", path), zap.Error(err))
	}
	return nil
}

// appendQueryParam adds a query parameter to a path, preserving any existing
// query string: /a?b=c -> /a?b=c&x=v.
func appendQueryParam(path, key, value string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + key + "=" + url.QueryEscape(value)
}

// getResponseBody retrieves the response body from the store.
func (s *ActiveScanner) getResponseBody(exchange *core.Exchange) string {
	if exchange.Response == nil {
		return ""
	}
	msg, err := s.store.Get(*exchange.Response)
	if err != nil {
		return ""
	}
	// Get body span
	bodySpan := msg.Shape.Body
	if bodySpan.IsEmpty() {
		return ""
	}
	return string(msg.Slice(bodySpan))
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetFindings returns all findings.
func (s *ActiveScanner) GetFindings() []*Finding {
	s.findingsMu.RLock()
	defer s.findingsMu.RUnlock()

	result := make([]*Finding, len(s.findings))
	copy(result, s.findings)
	return result
}

// ClearFindings clears all findings.
func (s *ActiveScanner) ClearFindings() {
	s.findingsMu.Lock()
	defer s.findingsMu.Unlock()
	s.findings = make([]*Finding, 0)
}

// PassiveScanner performs passive security scanning. With no BCheck corpus
// loaded it runs the built-in header/cookie checks; after LoadDir it runs the
// parsed passive BCheck set instead.
type PassiveScanner struct {
	store   *core.TrafficStore
	logger  *zap.Logger
	scope   *core.Scope
	passive []*bcheck.Check
	active  []*bcheck.Check
	// insertion holds the checks the active engine can dispatch once insertion
	// points exist (`given insertion point`, or any check carrying `send
	// payload`). They used to be counted and dropped; they are now counted *and*
	// kept for the active scanner — see ActiveChecks.
	insertion []*bcheck.Check
	// tools holds the checks that invoke an external tool via `run tool`. Never
	// passive; dispatchable only when the ActiveScanner has a runner — see
	// ActiveChecks and scanner's corpusActiveChecks.
	tools    []*bcheck.Check
	report   LoadReport
	coverage *CoverageTracker

	findings   []*Finding
	findingsMu sync.RWMutex
}

// NewPassiveScanner creates a passive scanner with the built-in header/cookie
// checks. Use LoadDir to run a PortSwigger BCheck corpus instead.
func NewPassiveScanner(store *core.TrafficStore, logger *zap.Logger) *PassiveScanner {
	return &PassiveScanner{
		store:    store,
		logger:   logger,
		findings: make([]*Finding, 0),
	}
}

// Scan performs passive scanning on an exchange.
func (s *PassiveScanner) Scan(exchange *core.Exchange) []*Finding {
	if s.coverage != nil {
		return s.scanBChecks(exchange)
	}

	var findings []*Finding

	// Check for missing security headers
	s.checkSecurityHeaders(exchange, &findings)

	// Check for information disclosure
	s.checkInfoDisclosure(exchange, &findings)

	// Check for cookie security issues
	s.checkCookieSecurity(exchange, &findings)

	// Store findings
	s.findingsMu.Lock()
	s.findings = append(s.findings, findings...)
	s.findingsMu.Unlock()

	return findings
}

func (s *PassiveScanner) checkSecurityHeaders(exchange *core.Exchange, findings *[]*Finding) {
	// Parse response headers from stored message
	respHeaders := s.getResponseHeaders(exchange)
	lines := strings.Split(respHeaders, "\r\n")

	hasXFrameOptions := false
	hasXContentTypeOptions := false
	hasCSP := false

	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "x-frame-options:") {
			hasXFrameOptions = true
		}
		if strings.HasPrefix(lower, "x-content-type-options:") {
			hasXContentTypeOptions = true
		}
		if strings.HasPrefix(lower, "content-security-policy:") {
			hasCSP = true
		}
	}

	if !hasXFrameOptions {
		*findings = append(*findings, &Finding{
			Name:        "Missing X-Frame-Options Header",
			Severity:    "low",
			Confidence:  "certain",
			Description: "The X-Frame-Options header is missing, making the site vulnerable to clickjacking",
			URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
			Method:      exchange.Method,
			Solution:    "Add X-Frame-Options: DENY or SAMEORIGIN header",
			Timestamp:   time.Now(),
		})
	}

	if !hasXContentTypeOptions {
		*findings = append(*findings, &Finding{
			Name:        "Missing X-Content-Type-Options Header",
			Severity:    "low",
			Confidence:  "certain",
			Description: "The X-Content-Type-Options header is missing, allowing MIME type sniffing",
			URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
			Method:      exchange.Method,
			Solution:    "Add X-Content-Type-Options: nosniff header",
			Timestamp:   time.Now(),
		})
	}

	if !hasCSP {
		*findings = append(*findings, &Finding{
			Name:        "Missing Content-Security-Policy Header",
			Severity:    "info",
			Confidence:  "certain",
			Description: "The Content-Security-Policy header is missing",
			URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
			Method:      exchange.Method,
			Solution:    "Implement a strict Content-Security-Policy",
			Timestamp:   time.Now(),
		})
	}
}

func (s *PassiveScanner) checkInfoDisclosure(exchange *core.Exchange, findings *[]*Finding) {
	respBody := s.getResponseBody(exchange)

	// Patterns for sensitive information
	patterns := map[string]string{
		`(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`:               "Email Address",
		`(?i)\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`:    "Credit Card Number",
		`(?i)(?:api[_-]?key|apikey|api_secret)["\s:=]+["']?[A-Za-z0-9_-]+["']?`: "API Key",
		`(?i)(?:password|passwd|pwd)["\s:=]+["']?[^\s"']+"'?`:                   "Password in Response",
		`(?i)\b[A-Fa-f0-9]{32}\b`:                                               "Potential Hash (MD5)",
	}

	for pattern, infoType := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		matches := re.FindAllString(respBody, -1)
		if len(matches) > 0 {
			*findings = append(*findings, &Finding{
				Name:        fmt.Sprintf("Information Disclosure: %s", infoType),
				Severity:    "medium",
				Confidence:  "tentative",
				Description: fmt.Sprintf("Potential %s found in response", infoType),
				URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
				Method:      exchange.Method,
				Evidence:    matches[0],
				Solution:    "Review and sanitize sensitive data from responses",
				Timestamp:   time.Now(),
			})
		}
	}
}

func (s *PassiveScanner) checkCookieSecurity(exchange *core.Exchange, findings *[]*Finding) {
	respHeaders := s.getResponseHeaders(exchange)

	// Find Set-Cookie headers
	lines := strings.Split(respHeaders, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "set-cookie:") {
			cookie := strings.TrimSpace(line[11:])

			// Check for Secure flag
			if !strings.Contains(strings.ToLower(cookie), "; secure") && exchange.TLS {
				*findings = append(*findings, &Finding{
					Name:        "Cookie Missing Secure Flag",
					Severity:    "medium",
					Confidence:  "certain",
					Description: "Cookie is set without Secure flag over HTTPS",
					URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
					Method:      exchange.Method,
					Evidence:    cookie[:min(len(cookie), 50)],
					Solution:    "Add Secure flag to all cookies",
					Timestamp:   time.Now(),
				})
			}

			// Check for HttpOnly flag
			if !strings.Contains(strings.ToLower(cookie), "; httponly") {
				*findings = append(*findings, &Finding{
					Name:        "Cookie Missing HttpOnly Flag",
					Severity:    "low",
					Confidence:  "certain",
					Description: "Cookie is set without HttpOnly flag",
					URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
					Method:      exchange.Method,
					Evidence:    cookie[:min(len(cookie), 50)],
					Solution:    "Add HttpOnly flag to session cookies",
					Timestamp:   time.Now(),
				})
			}

			// Check for SameSite flag
			if !strings.Contains(strings.ToLower(cookie), "; samesite") {
				*findings = append(*findings, &Finding{
					Name:        "Cookie Missing SameSite Flag",
					Severity:    "low",
					Confidence:  "certain",
					Description: "Cookie is set without SameSite flag",
					URL:         fmt.Sprintf("%s://%s:%d%s", map[bool]string{true: "https", false: "http"}[exchange.TLS], exchange.Host, exchange.Port, exchange.Path),
					Method:      exchange.Method,
					Evidence:    cookie[:min(len(cookie), 50)],
					Solution:    "Add SameSite=Strict or SameSite=Lax flag",
					Timestamp:   time.Now(),
				})
			}
		}
	}
}

// getResponseBody retrieves the response body from the store.
func (s *PassiveScanner) getResponseBody(exchange *core.Exchange) string {
	if exchange.Response == nil {
		return ""
	}
	msg, err := s.store.Get(*exchange.Response)
	if err != nil {
		return ""
	}
	bodySpan := msg.Shape.Body
	if bodySpan.IsEmpty() {
		return ""
	}
	return string(msg.Slice(bodySpan))
}

// getResponseHeaders retrieves the response headers from the store.
func (s *PassiveScanner) getResponseHeaders(exchange *core.Exchange) string {
	if exchange.Response == nil {
		return ""
	}
	msg, err := s.store.Get(*exchange.Response)
	if err != nil {
		return ""
	}
	// Return full raw message for header parsing
	return string(msg.Raw())
}

// GetFindings returns all passive findings.
func (s *PassiveScanner) GetFindings() []*Finding {
	s.findingsMu.RLock()
	defer s.findingsMu.RUnlock()

	result := make([]*Finding, len(s.findings))
	copy(result, s.findings)
	return result
}
