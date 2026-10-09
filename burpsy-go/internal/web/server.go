package web

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/burpsy-go/burpsy/internal/advisory"
	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/browser"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/dominvader"
	"github.com/burpsy-go/burpsy/internal/extension"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/organizer"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/pool"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/schedule"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/sequencer"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/sitemap"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"github.com/burpsy-go/burpsy/internal/upstream"
	"go.uber.org/zap"
)

// Server represents the web API server.
type Server struct {
	store  *core.TrafficStore
	scope  *core.Scope
	logger *zap.Logger
	// proxyBind and webBind are the -proxy and -web flag values the binary was
	// started with, so the Settings page can show where it listens.
	proxyBind string
	webBind   string
	// reissue is the one-shot token table behind "request in browser"
	// (burpsy-react-ui-7rk0): minted by the API the operator's right-click reaches, spent by
	// the fetch their browser makes, swept by expiry. See api_browser_reissue.go for why the
	// tokens are random, one-shot, and five minutes long.
	reissue browserReissueTokens
	// domEngine is the -dom flag value, reported by /api/stats. Empty means no engine was named.
	domEngine string
	// tlsInterception reports whether the server is configured for TLS
	// interception (determined by whether a CA cert PEM exists).
	tlsInterception bool
	mux             *http.ServeMux
	// allowedHosts are the Host header values this console answers to for MUTATING requests
	// (burpsy-react-ui-s19k). Empty means loopback only, which is the setting that stops a DNS
	// rebinding attack; a non-empty set is an operator who deliberately bound the console to
	// something reachable and has named what they reachable it as.
	//
	// Absent from the default on purpose: the safe reading must be the one a caller gets by doing
	// nothing, because a flag nobody sets cannot be the thing standing between a hostile page and an
	// attack.
	allowedHosts map[string]bool
	// guarded is mux behind the cross-site gate, and it is what ListenAndServe serves. A separate
	// field rather than reassigning mux, because every test in this package drives s.mux directly and
	// must keep doing so: those tests are about handler behaviour, and the gate has its own.
	guarded http.Handler
	// confirms holds the live one-time confirmations the unattended-caller gate spends
	// (burpsy-react-ui-ejp5). On the Server because the gate is a per-process authorisation
	// primitive: a token minted in one process says nothing about another, which is the right
	// reading for a console an operator runs rather than a service with many users.
	confirms *confirmStore
	// confirmMux serves the mint endpoints, kept OFF s.mux so a gated route cannot shadow its own
	// /confirm suffix and so the patterns do not enter the route manifest's remit.
	confirmMux     http.Handler
	sender         *sender.Sender
	scanner        *scanner.ActiveScanner
	passiveScanner *scanner.PassiveScanner
	// toolRunner is the allowlist runner `run tool` statements dispatch through
	// on the lazily built audit scanner. Nil means tool execution is disabled;
	// corpus checks that need a tool are counted at load and never admitted.
	toolRunner bcheck.ToolRunner
	findings   *core.FindingStore
	// advisories is the issue-definition catalogue. Nil is a supported state and means every finding
	// falls back to its own description and remediation — the catalogue enriches findings, it is
	// never required to render one.
	advisories         *advisory.Catalogue
	sitemap            *sitemap.SiteMap
	sessionCoordinator *session.Coordinator
	// prompts is the pending browser-recovery prompt registry behind the session rule action of
	// the same name (burpsy-react-ui-dq1g): the task that hit the action blocks on the prompter
	// seam, and the answer arrives here from the console's modal. Constructed in NewServer like
	// the other registries; nil only in a Server built by direct struct literal in a test that
	// never touches the prompt routes.
	prompts      *sessionPrompts
	matchReplace *matchreplace.RuleSet
	toolLog      *toollog.ToolLog
	organizer    *organizer.Store
	loginRuns    *sessionLoginRuns
	intercept    *intercept.Engine
	persist      *persist.Store
	// seqSettings is Burp's sequencer.* analysis configuration (burpsy-react-ui-nm81), project-level:
	// restored by WithPersist, so a project switch brings the incoming project's settings. A nil map
	// means "never set" and reads as sequencer.DefaultSettings. Guarded by seqMu.
	seqMu       sync.Mutex
	seqSettings sequencer.Settings
	// browser is the operator's pre-wired Chromium launcher (burpsy-react-ui-bufa), created on first
	// use; see api_browser.go.
	browserOnce sync.Once
	browser     *browser.Launcher
	// domInvader is the operator-side DOM auditor's state (burpsy-react-ui-wl94): the canary, the
	// switch and the reported source/sink hits. The browser bakes its config from this on launch and
	// the report endpoint feeds it.
	domInvader *dominvader.Store
	// authz holds the project's access-control test identities (burpsy-react-ui-cr37).
	authz authzState
	// domExtDir is the last materialised DOM-auditor extension directory, removed before the next
	// launch rewrites it so the temp area does not accumulate one per launch.
	domExtDir string
	// webAddr is the address ListenAndServe bound, so the DOM auditor can tell its extension where to
	// report. Empty in tests, which never serve.
	webAddr string
	// poc is the one-shot PoC page host for "Test in browser" (burpsy-react-ui-0z10): a
	// listener on its own loopback port, deliberately NOT part of s.mux or the route
	// manifest, because its whole reason to exist is that generated PoCs are served off
	// the console origin. Nil until the first PoC URL is minted; pocMu guards that
	// lazy start.
	poc   *pocHost
	pocMu sync.Mutex
	// scanBaseline is the scan configuration as launched, before any project's saved overrides — what
	// a project that saved none gets (burpsy-react-ui-z4ml). Captured on the first restore.
	scanBaseline *scanner.ScanConfig
	// Custom history/Intruder extractor columns (burpsy-react-ui-28n8), project-level; see
	// api_history_extractors.go.
	// consolidation is the operator's issue-consolidation policy, remembered so a finding store
	// swapped in by WithFindings gets it too (burpsy-react-ui-oorl). Nil until one is set or restored.
	consolidationMu sync.Mutex
	consolidation   *core.ConsolidationPolicy
	histExtractMu   sync.Mutex
	histExtractDefs []sessionExtractDto
	histExtractRun  []*session.Extraction
	// tlsPolicy is the proxy's live TLS interception policy, shared so the web API can list and
	// edit passthrough rules while the proxy keeps matching against the same list. Nil is a
	// supported state (direct construction in tests); the passthrough endpoint says so rather
	// than serving an empty list nothing could ever change.
	tlsPolicy *proxy.TlsPolicy
	// proxyOptions is the proxy's live option set — response modification rules and the
	// Accept-Encoding strip — shared with the relay for the same reason tlsPolicy is: a
	// settings panel describing rules the relay does not apply is the failure two option
	// sets produce. Nil is supported; the endpoint reports it rather than serving a panel
	// that could not change anything.
	proxyOptions *proxy.Options
	// proxyServer is the relay itself, for the listener surface: the console reads
	// where it is bound and moves it at runtime (burpsy-react-ui-77m, scope (1)).
	// Nil is supported; the endpoint reports it rather than inventing an address.
	proxyServer *proxy.Server
	liveAudit   *LiveAuditState
	// auditItems is the audit queue: what the engine decided about each item it was handed, retained
	// so /api/scanner/audit-items can serve it. Built in NewServer rather than lazily, unlike
	// `captures`: every audit path in this package attaches it to the AuditConfig it runs under, so a
	// nil here would mean the first audit of a session silently did not appear in the queue.
	//
	// Not persisted. The queue is a statement about what this process did with this process's
	// budgets and breakers, and a row restored from a previous run would carry thresholds that are no
	// longer in force — findings and the task log are the durable record.
	auditItems *scanner.AuditItemLedger
	tasks      *dash.Registry
	// attacks is the live table of Intruder attacks this process is running, keyed by dashboard task
	// id, so pause/resume/stop can reach one from another connection while /api/intruder/run holds the
	// attack's own request open. See api_intruder_control.go.
	attacks *attackRegistry
	// pools is the operator's saved resource pools: named limits every tool can reference instead of
	// re-specifying its own. Never nil — an empty registry is the honest starting state, and every
	// tool runs under its own documented default until a pool is saved and named.
	pools *pool.Registry
	// schedules is the saved set of scheduled tasks plus the clock decisions over them. The kinds it
	// can start are registered in registerScheduleKinds; nothing consults the clock until
	// ListenAndServe starts runScheduler, which is why schedulerRunning is served on the API.
	schedules *schedule.Runner
	// schedulerRunning says whether anything is ticking. Atomic because it is written by
	// ListenAndServe's scheduler goroutine and read by a request handler.
	schedulerRunning atomic.Bool
	// crawls retains recent crawl reports, keyed by the task id that produced them, so the dashboard
	// row and the coverage report are one identity rather than two numbers to correlate by hand.
	crawls *crawlRuns
	// discoveries retains recent content-discovery runs, keyed by task id for the same reason crawls
	// are — see api_discovery.go.
	discoveries *discoveryRuns
	// hiddenInputs retains recent hidden-input guessing runs (burpsy-react-ui-wlz8), keyed by task id.
	hiddenInputs *hiddenInputRuns
	// externalTools is the operator's -tools allowlist, the one that also gates `run tool` bchecks.
	// Nil means external delegation is off, and /api/discovery refuses and says which name is missing
	// rather than answering with an empty result. The server never builds one: which binary may be
	// executed against a client's system is operator policy, like the corpus.
	externalTools map[string]string
	// blindxss is the blind-XSS callback channel, or nil when none was configured. Nil is a supported
	// state and is reported as such — see api_blindxss.go on why an empty hit list is not an answer.
	blindxss *blindXSSChannel
	// events is the DASH-02 event log: what the tool *did*, as opposed to toolLog's what-it-*sent*.
	// Two logs because they count different things — see internal/dash/events.go.
	events *dash.EventLog
	// caCertPEM is the CA certificate the proxy signs leaves with, served at /ca.crt so a browser can
	// be told to trust it. Nil when interception is off, and then the route reports that rather than
	// serving an empty file — see handleCACert.
	caCertPEM []byte
	// uninteresting holds the header names the Comparer discounts — W6 #81/#82. Always non-nil:
	// built in NewServer so every code path can consult it without a nil check, and so the
	// response-side defaults are in force from the first request rather than after a first PUT.
	uninteresting *uninterestingHeaders
	// tlsEngine is the live signing engine, when TLS interception is on. Held so the CA can be
	// replaced at runtime (POST /api/proxy/ca) and so /ca.crt serves whichever CA is in force
	// rather than the bytes this process started with — an operator who imports a CA and then
	// downloads the certificate must receive the one that is actually signing.
	tlsEngine *proxy.TlsEngine
	// caDir is where an imported CA is persisted, so it survives a restart. Empty means the
	// import endpoint installs the CA for this process only and says so.
	caDir string
	// captures holds sequencer capture runs, built on first use by captureSet(). Lazy rather than in
	// NewServer because a session that never runs a capture should not allocate the table, and because
	// every existing test constructs a Server directly — see api_sequencer_capture.go.
	captures    *sequencerCaptures
	captureOnce sync.Once
	// collaborator holds what the Collaborator tool knows that the out-of-band channel does not:
	// which payload addresses an operator minted, and how the last read of the interaction log went.
	// The channel itself lives on the ActiveScanner and is deliberately NOT duplicated here — see
	// api_collaborator.go on why a second registration would show interactions no finding correlates
	// with. Lazy for the same reasons as captures above.
	collaborator *collaboratorHub
	// collabStateBase is -collaborator-state-dir: where a channel installed from the console keeps its
	// identity, one directory per server (d657). Empty keeps a fresh identity per process.
	collabStateBase  string
	collaboratorOnce sync.Once
	// extensions is the plugin host: the operator's -plugins allowlist and the child processes it
	// admits. Lazily replaced by an empty host on first use (extensionOnce), so a Server built without
	// one reports an allowlist of zero rather than 503 — see api_extensions.go.
	extensions    *extension.Host
	extensionOnce sync.Once
	// upstreamProxy is the per-destination upstream proxy policy /api/network/proxy edits. Held by
	// reference and shared with internal/proxy's listener and every sender this process builds, so an
	// edit reaches the next dial on both egress paths without a restart. Nil means the process was
	// built without one, and the handler reports that rather than pretending an edit would take
	// effect — see handleNetworkProxy.
	upstreamProxy *upstream.Policy
	// upstreamCarrier is the global SOCKS layer, shared with the sender and the proxy so one
	// Settings edit reaches every egress surface. Distinct from upstreamProxy because it answers a
	// different question — "which proxy carries this host" versus "what opens the socket to reach
	// that proxy" — and because a surface can hold one without the other (burpsy-react-ui-mr83
	// part 3).
	upstreamCarrier *upstream.Carrier
	// platformAuth and clientCerts are the Settings → Network stores: per-host HTTP
	// credentials and per-host TLS client identities. Built lazily by platformAuthStore()
	// and clientCertStore() so a directly-constructed Server never serves a nil one, and
	// shared with internal/sender and the proxy when cmd/burpsy wires them — see
	// WithNetAuth.
	platformAuth *netauth.Credentials
	clientCerts  *netauth.ClientCerts
	netAuthOnce  sync.Once
	// netAuthRestoreNotes is why a persisted client-certificate binding could not be
	// rebuilt at startup, reported by the GET rather than dropped. See
	// WithNetAuthRestoreNotes.
	netAuthRestoreNotes []string
	// live is the change-event hub behind /api/events: every store the UI reads signals it, and it
	// coalesces those signals into "this kind changed" frames the browser refetches on. See events.go
	// for why the frames carry no data and why the producer side is atomics only.
	live *eventHub
}

// maxRequestBodyBytes bounds any single API request body. Generous enough for
// the repeater's raw requests and large payload sets, bounded enough that a
// runaway upload cannot exhaust memory. 16 MiB covers the largest legitimate
// operator paste the UI is expected to send.
const maxRequestBodyBytes = 16 * 1024 * 1024

// NewServer creates a new web server.
func NewServer(store *core.TrafficStore, scope *core.Scope) *Server {
	s := &Server{
		store:              store,
		scope:              scope,
		logger:             zap.NewNop(),
		mux:                http.NewServeMux(),
		confirms:           newConfirmStore(),
		sender:             sender.NewSender(sender.DefaultSenderConfig()),
		findings:           core.NewFindingStore(),
		advisories:         loadAdvisories(),
		sitemap:            sitemap.New(),
		sessionCoordinator: session.NewCoordinator(zap.NewNop()),
		matchReplace:       matchreplace.NewRuleSet(),
		uninteresting:      newUninterestingHeaders(),
		toolLog:            toollog.New(),
		organizer:          organizer.New(),
		loginRuns:          newSessionLoginRuns(),
		prompts:            newSessionPrompts(),
		intercept:          intercept.NewEngine(),
		auditItems:         scanner.NewAuditItemLedger(scanner.DefaultAuditItemCap),
		tasks:              dash.NewRegistry(),
		attacks:            newAttackRegistry(),
		pools:              pool.New(),
		schedules:          schedule.NewRunner(),
		crawls:             newCrawlRuns(),
		discoveries:        newDiscoveryRuns(),
		hiddenInputs:       newHiddenInputRuns(),
		events:             dash.NewEventLog(),
		live:               newEventHub(),
		domInvader:         dominvader.NewStore(),
	}
	// One wiring call gives every task in the process — including a crawl registered from outside this
	// package — a started and a finished event, without either side knowing about the other.
	s.tasks.WithEvents(s.events)
	// The site map subscribes to the store here rather than rebuilding itself when
	// the tab is opened — see the sitemap package docs (CRAWL-05). Constructed
	// before any traffic can arrive, which is the ordering ObserveExchanges needs.
	s.installSuiteScopePredicate()
	s.sitemap.Follow(store)
	// The traffic store's two live signals are installed once, here, because the
	// store is never replaced after construction — there is no WithStore. The
	// exchange one goes through ObserveExchanges, which appends rather than
	// replaces, so installing it anywhere re-entrant would double-count.
	store.ObserveExchanges(func(*core.Exchange) { s.live.notify(changeHistory) })
	store.OnWsChange(func() { s.live.notify(changeWS) })
	// Registered before any restore can happen, so a schedule loaded from disk finds its kind already
	// known. The runner refuses a kind it cannot start, and a restore that ran first would have
	// nothing to check against.
	s.registerScheduleKinds()
	// The intercept engine needs the scope for Burp's "Only intercept in-scope messages". Attached
	// here rather than passed to NewEngine so the engine keeps no constructor dependency on it, and
	// so the pointer is provably the same *core.Scope the server and the relay hold — a second scope
	// object would let the toggle filter against rules the operator cannot see.
	s.intercept.SetScope(scope)
	s.followLive()
	s.setupRoutes()
	return s
}

// followLive installs the live-update hub's change signals on every replaceable store the server
// currently holds.
//
// Called from NewServer and again from each With* that swaps one of those stores out, which is safe
// because every hook here is a single slot: re-installing replaces rather than adds. A store that was
// replaced keeps its hook pointing at the same hub, which costs one atomic increment on an object
// nothing reads any more — the same bounded, silent waste WithSitemap documents, and the same reason it
// is not worth an unsubscribe protocol.
func (s *Server) followLive() {
	s.findings.OnChange(func() { s.live.notify(changeIssues) })
	// Installed here for the same reason as the hooks around it: it is a single slot on a store that
	// a With* may have just replaced, so it has to follow the store rather than the constructor. It
	// tells the finding store which catalog rows dedup per host rather than per path, knowledge that
	// only the scanner's check registry has — see scanner.DedupPolicy.
	s.findings.SetDedupPolicy(scanner.DedupPolicy())
	s.reapplyConsolidation()
	s.toolLog.OnChange(func() { s.live.notify(changeToolLog) })
	s.domInvader.OnChange(func() { s.live.notify(changeDomInvader) })
	s.events.OnChange(func() { s.live.notify(changeDashboard) })
	s.intercept.OnChange(func() { s.live.notify(changeIntercept) })
}

// WithLogger sets the logger.
func (s *Server) WithLogger(logger *zap.Logger) *Server {
	s.logger = logger
	return s
}

// WithSender sets the HTTP sender the request-originating handlers send through.
//
// It is the raw network layer and authorises nothing on its own. Every handler that originates a
// request binds it into a sender.AuthorisedSender for that request's own authority first — the
// intruder (api_tools.go) and the session macro runner (api_session.go) both do — so the engagement
// scope decides about the request line before the dial. The repeater is the one deliberate exception
// and states its own weaker host-level check where it makes it.
func (s *Server) WithSender(snd *sender.Sender) *Server {
	s.sender = snd
	return s
}

// WithToolRunner attaches the allowlist runner `run tool` statements dispatch
// through, for the lazily built audit scanner. Without one, corpus checks that
// need a tool are counted at load and never admitted — see
// scanner.corpusActiveChecks. The server never builds a runner of its own;
// tool execution is operator policy, supplied from the command line like the
// corpus itself.
func (s *Server) WithToolRunner(r bcheck.ToolRunner) *Server {
	s.toolRunner = r
	return s
}

// WithExternalTools attaches the operator's -tools allowlist, as the raw name=path map, for the
// surfaces that delegate a whole phase to an external binary rather than running one per insertion
// point — today /api/discovery and its `ffuf`.
//
// It is the same map WithToolRunner's runner was built from, and it is passed separately rather than
// read back out of the runner because the two consume it differently: bcheck.ToolRunner is an
// interface that resolves a name per statement, while extscan.Config wants the map itself so it can
// answer "could this tool run at all" before any work is registered. Passing nil (no -tools) leaves
// delegation off and the route reporting which name is missing.
func (s *Server) WithExternalTools(tools map[string]string) *Server {
	s.externalTools = tools
	return s
}

// WithExtensions attaches the plugin host the EXTENDER routes drive.
//
// Supplied from the command line like the -tools allowlist and for the same reason: which executables
// may run is operator policy, and the web server has no business inventing one. Passing nil leaves the
// lazily built empty host in place, which reports an allowlist of zero rather than disabling the
// surface — the Extensions tab must be able to say "nothing is allowlisted, here is the flag".
//
// The caller keeps the host and is responsible for Close: the processes outlive any one request and
// have to be stopped when the process is, which the web server's shutdown path does not model.
func (s *Server) WithExtensions(host *extension.Host) *Server {
	if host != nil {
		s.extensions = host
		// Marked done so extensionHost() does not replace a real host with an empty one on first use.
		s.extensionOnce.Do(func() {})
	}
	return s
}

// WithScanner sets the active scanner used by the audit endpoint.
//
// The pool pacer is attached here rather than left to the caller, for the same reason
// SetDedupPolicy is installed in followLive: it is knowledge this package has and the process that
// builds a scanner does not. Without it an audit that named a resource pool would run unpaced while
// the reply said which pool it ran under — a lie of exactly the shape this unit exists to remove.
// The pacer reads the pool from the audit's own context, so one scanner serves every pool; see
// api_scanner_audit.go's auditContext.
func (s *Server) WithScanner(scan *scanner.ActiveScanner) *Server {
	if scan != nil {
		// Pace and the suite-wide pause together: both are things the server owns and the engine
		// cannot know about (burpsy-react-ui-cijs). GateCheck is nil-receiver safe, so a server
		// with no task registry attaches a gate that never holds.
		scan = scan.WithPace(pool.ContextPacer{}).WithSuiteGate(s.tasks.GateCheck)
	}
	s.scanner = scan
	return s
}

// WithCollaboratorStateDir sets where a Collaborator channel installed from the console keeps its
// identity across restarts (-collaborator-state-dir, burpsy-react-ui-d657).
func (s *Server) WithCollaboratorStateDir(dir string) *Server {
	s.collabStateBase = dir
	return s
}

// WithPassiveScanner sets the passive scanner used to report whether BCheck
// scanning is enabled on live traffic.
func (s *Server) WithPassiveScanner(scan *scanner.PassiveScanner) *Server {
	s.passiveScanner = scan
	return s
}

// WithFindings sets the findings store.
func (s *Server) WithFindings(fs *core.FindingStore) *Server {
	s.findings = fs
	s.followLive()
	return s
}

// WithTlsPolicy attaches the proxy's live TLS policy so passthrough rules can be listed and edited
// at runtime. Nil (the default in tests) leaves the endpoint reporting honestly that no policy is
// attached rather than pretending to manage one.
func (s *Server) WithTlsPolicy(policy *proxy.TlsPolicy) *Server {
	s.tlsPolicy = policy
	return s
}

// WithProxyOptions attaches the proxy's live option set so the response modification rules and the
// Accept-Encoding strip can be listed and edited at runtime. Nil (the default in tests) leaves the
// endpoint reporting that no option set is attached rather than serving a panel whose switches
// would do nothing — the same honesty WithTlsPolicy's nil state holds.
func (s *Server) WithProxyOptions(options *proxy.Options) *Server {
	s.proxyOptions = options
	return s
}

// WithProxyServer attaches the relay itself, so the console can inspect and re-bind its
// listener. Nil (the default in tests) leaves /api/proxy/listener reporting that no
// listener is attached rather than an address nothing serves.
func (s *Server) WithProxyServer(server *proxy.Server) *Server {
	s.proxyServer = server
	return s
}

// WithIntercept attaches the shared intercept engine. The web API and the proxy must hold the same instance, or edits here would not affect the hold queue.
func (s *Server) WithIntercept(engine *intercept.Engine) *Server {
	s.intercept = engine
	s.followLive()
	return s
}

// WithLiveAudit attaches the live audit state, or nil to report the feature unwired.
func (s *Server) WithLiveAudit(la *LiveAuditState) *Server {
	s.liveAudit = la
	return s
}

// WithCACertPEM supplies the CA certificate the proxy signs leaves with, so /ca.crt can serve it.
//
// Passed in rather than read from disk here: the web server has no business knowing where the CA
// directory is, and the process that generated or loaded the CA already holds the bytes. Nil or empty
// leaves the route reporting that interception is off, which is what the UI's CA link keys off.
// WithTLSEngine supplies the live signing engine and the directory an imported CA is written to.
//
// Separate from WithCACertPEM because the two answer different questions: that one supplies bytes to
// serve, this one supplies the thing that can be *changed*. A Server without an engine still serves
// /ca.crt from the PEM it was given and refuses imports, which is the correct behaviour when TLS
// interception is off.
func (s *Server) WithTLSEngine(engine *proxy.TlsEngine, caDir string) *Server {
	s.tlsEngine = engine
	s.caDir = caDir
	return s
}

// currentCACertPEM is the CA to serve at /ca.crt: the engine's, when there is one, because it may
// have been replaced since startup. Falls back to the PEM passed at construction.
func (s *Server) currentCACertPEM() []byte {
	if s.tlsEngine != nil {
		if live := s.tlsEngine.CertPEM(); len(live) > 0 {
			return live
		}
	}
	return s.caCertPEM
}

func (s *Server) WithCACertPEM(pem []byte) *Server {
	s.caCertPEM = pem
	s.tlsInterception = pem != nil
	return s
}

// WithBindAddrs records the -proxy and -web bind addresses the binary was
// started with, so the Settings page can show where the listeners actually are
// rather than leaving the operator to check the process logs.
func (s *Server) WithBindAddrs(proxyBind, webBind string) *Server {
	s.proxyBind = proxyBind
	s.webBind = webBind
	return s
}

// WithDOMEngine records the -dom value, for the same reason WithBindAddrs records the binds: the
// operator should read the console rather than the process logs to learn what this process can do.
// The label is reported beside whether the DOM families can dispatch at all, and the two are not
// derived from each other — see StatsView.
func (s *Server) WithDOMEngine(label string) *Server {
	s.domEngine = label
	return s
}

// WithPersist attaches the durable SQLite mirror. It restores the stores the
// web server owns (match & replace rules, session rules, organizer, tool log)
// and wires the tool log's write-through sink. The shared stores (history,
// findings, scope) are restored by the caller before the server is built;
// passing nil disables persistence.
func (s *Server) WithPersist(p *persist.Store) *Server {
	s.persist = p
	if p != nil {
		if err := p.Restore(nil, nil, nil, s.matchReplace, s.sessionCoordinator, s.organizer, s.toolLog); err != nil {
			s.logger.Warn("failed to restore web-owned state", zap.Error(err))
		}
		// Burp's "Default Proxy interception state" (burpsy-react-ui-7vy): what the intercept
		// switch reads at start. "restore" reuses the last live state; the default is off, the
		// seed every existing session used — a preference nobody wrote must not turn
		// interception on by surprise.
		if s.intercept != nil {
			switch p.LoadInterceptStartup() {
			case "on":
				s.intercept.SetEnabled(true)
			case "restore":
				s.intercept.SetEnabled(p.LoadInterceptLive())
			}
		}
		s.toolLog.SetPersistenceSink(p.SaveToolLog)
		s.restorePools(p)
		// Sequencer analysis settings are project-level, so they are (re)loaded here — on startup and
		// on every in-console project switch, which re-runs WithPersist. A project that never saved any
		// reads as Burp's defaults rather than keeping the outgoing project's switches.
		s.restoreSequencerSettings(p)
		// The browser's settings and its default profile directory follow the project too — two
		// engagements' browsers must not share cookies (burpsy-react-ui-bufa).
		s.restoreBrowserSettings()
		// Project-level scan state — the scan overrides and the live sweep's seen ledger — follows the
		// project too (burpsy-react-ui-z4ml).
		s.restoreProjectScanState(p)
		// Custom extractor columns are project-level too (burpsy-react-ui-28n8).
		s.restoreHistoryExtractors(p)
		// So is the issue consolidation policy (burpsy-react-ui-oorl).
		s.restoreFindingConsolidation(p)
		// And the access-control test identities (burpsy-react-ui-cr37).
		s.restoreAuthzIdentities(p)
		// And whether captured responses are scanned for leaked secrets (burpsy-react-ui-8j0d).
		s.restoreSecretDetection(p)
	}
	return s
}

// restorePools loads the saved pools and schedules and installs their write-through sinks.
//
// Not part of persist.Store.Restore, which is already seven positional stores wide and is called by
// main.go for the shared state: these two are owned entirely by this server, so it asks for them
// itself. See internal/persist/pools.go.
//
// Every refusal is logged with its reason and then counted, matching the session-rule restore: a
// pool that vanished in silence would leave a schedule referencing a name nothing holds, and the
// scheduled run would fall back to bounds nobody chose at the hour nobody is watching. The order is
// pools first, then schedules, so a schedule's pool reference resolves against the set that was
// actually restored rather than against an empty one.
func (s *Server) restorePools(p *persist.Store) {
	pools, err := p.LoadPools()
	if err != nil {
		s.logger.Warn("failed to load saved resource pools", zap.Error(err))
	} else if refused := s.pools.Restore(pools); len(refused) > 0 {
		for _, rerr := range refused {
			s.logger.Warn("a saved resource pool was refused on load", zap.Error(rerr))
		}
		s.logger.Warn("saved resource pools were not fully restored",
			zap.Int("restored", s.pools.Len()), zap.Int("refused", len(refused)))
	}
	schedules, err := p.LoadSchedules()
	if err != nil {
		s.logger.Warn("failed to load saved schedules", zap.Error(err))
	} else if refused := s.schedules.Restore(schedules); len(refused) > 0 {
		for _, rerr := range refused {
			s.logger.Warn("a saved schedule was refused on load", zap.Error(rerr))
		}
		s.logger.Warn("saved schedules were not fully restored",
			zap.Int("restored", s.schedules.Len()), zap.Int("refused", len(refused)))
	}
	// Installed after the restore, not before: a sink armed first would fire on the restore itself and
	// write the loaded set straight back — harmless for pools, but for schedules it would persist the
	// set *before* the first tick had a chance to act on a missed window, and a crash in between would
	// then have rewritten nothing. Arming afterwards means the first write is a real change.
	//
	// Both persist the whole ordered list, matching SaveSessionRules: the lists are operator-sized
	// (200 each), so a diff would be more machinery than it saves.
	s.pools.OnChange(func() { p.SavePools(s.pools.List()) })
	s.schedules.OnChange(func() { p.SaveSchedules(s.schedules.List()) })
}

// WithUpstreamCarrier attaches the global SOCKS layer.
//
// The SAME instance must be handed to the sender and the proxy, for the reason WithUpstreamProxy
// says: two carriers would let the panel describe a layer that only one surface honours.
func (s *Server) WithUpstreamCarrier(carrier *upstream.Carrier) *Server {
	if carrier != nil {
		s.upstreamCarrier = carrier
		// Attached here, the way WithUpstreamProxy does, so the panel's `attached` field reports the
		// surfaces that actually carry the layer. A carrier reported as configured with no surface
		// listed is the state an operator cannot act on: they cannot tell which dial paths the setting
		// reaches (burpsy-react-ui-mr83 part 3).
		carrier.Attach("web")
	}
	return s
}

// WithUpstreamProxy attaches the upstream proxy policy /api/network/proxy edits.
//
// The same object the proxy listener and every sender hold, so an edit made in the console applies to
// the next connection either of them opens. Passing nil leaves the route reporting that no policy is
// wired, which is the honest answer for a process built without one: a settings panel that accepted
// rules nothing consults would be the exact defect Unit 9 exists to close.
func (s *Server) WithUpstreamProxy(policy *upstream.Policy) *Server {
	s.upstreamProxy = policy
	if policy != nil {
		policy.Attach("web")
	}
	return s
}

// ---- write-through helpers ---------------------------------------------------------------------

// The state below is replaced wholesale on each mutation (small tables), so the
// handlers call save-the-whole-* after changing it. Appended state (messages,
// exchanges, findings, tool log) mirrors through the stores' sinks instead.

func (s *Server) persistScope() {
	if s.persist != nil {
		s.persist.SaveScope(s.scope.Rules())
	}
}

func (s *Server) persistMatchReplace() {
	if s.persist != nil {
		s.persist.SaveMatchRules(s.matchReplace.Rules(), persist.MatchRuleSettings{
			UpdateContentLength: s.matchReplace.UpdateContentLength(),
			InScopeOnly:         s.matchReplace.InScopeOnly(),
		})
	}
}

func (s *Server) persistSessionRules() {
	if s.persist != nil {
		s.persist.SaveSessionRules(s.sessionCoordinator.AllRules())
	}
}

func (s *Server) persistUpstreamProxy() {
	if s.persist != nil && s.upstreamProxy != nil {
		s.persist.SaveUpstreamProxy(s.upstreamProxy)
	}
}

func (s *Server) persistOrganizer() {
	if s.persist != nil {
		s.persist.SaveOrganizer(s.organizer.List())
		// Mirrored alongside the items on purpose: an item names its collection by id, so saving one
		// table without the other would restore items into a group no longer defined.
		s.persist.SaveOrganizerCollections(s.organizer.Collections())
	}
}

// persistPlatformAuth and persistClientCerts mirror the network-authentication rules.
//
// These are the two write-through helpers that move a secret, so what they hand over is
// worth naming: netauth's Secrets() accessors, which are the package's one deliberate
// hole in "no secret leaves here" and exist for this caller and no other. Everything else
// in the process reads the redacted views. internal/persist's own doc records why the
// stored form is plaintext and what an operator should conclude from that.

func (s *Server) persistPlatformAuth() {
	if s.persist != nil {
		s.persist.SavePlatformAuth(s.platformAuthStore().Secrets())
	}
}

func (s *Server) persistClientCerts() {
	if s.persist != nil {
		s.persist.SaveClientCerts(s.clientCertStore().Secrets())
	}
}

// platformAuthStore and clientCertStore return the attached store, building an empty one
// on first use.
//
// Lazy rather than allocated in NewServer for the reason captureSet() is: every test in
// this package constructs a Server directly and most never touch this surface. What they
// buy over a nil check at each call site is that the handlers cannot serve a nil store —
// GET answers an honestly empty list instead of panicking, and a POST to a Server that
// nobody wired still stores the rule rather than dropping it. Whether the rule is
// actually *presented* is a separate question, and one the GET answers out loud through
// presented_on_egress rather than leaving to inference.
func (s *Server) platformAuthStore() *netauth.Credentials {
	s.netAuthOnce.Do(s.initNetAuth)
	return s.platformAuth
}

func (s *Server) clientCertStore() *netauth.ClientCerts {
	s.netAuthOnce.Do(s.initNetAuth)
	return s.clientCerts
}

// initNetAuth fills in whichever of the two stores was never attached. One Once for both
// because WithNetAuth sets both together, so there is one moment at which they are known.
func (s *Server) initNetAuth() {
	if s.platformAuth == nil {
		s.platformAuth = netauth.NewCredentials()
	}
	if s.clientCerts == nil {
		s.clientCerts = netauth.NewClientCerts()
	}
}

// WithNetAuth attaches the platform-authentication rules and client-certificate bindings
// the Network settings panel edits.
//
// # The stores are shared, and they have to be
//
// The same two pointers are read by three places that cannot see each other: this API
// writes them, internal/sender presents them on every egress, and the proxy's upstream
// leg presents the certificate on an intercepted connection. cmd/burpsy therefore builds
// them once, before either server, and hands the same pointers to all three — see the
// wiring there. Anything else would give the operator a panel editing one copy while the
// wire carried another.
//
// The sender's half is a constructor-time property (sender.CarriesPlatformAuth explains
// why an http.Transport's dial hook cannot honestly be rewritten later), so this method
// deliberately does not try to retrofit an already-built sender. It attaches the stores
// the API edits; whether the attached sender carries them is reported by the GET rather
// than assumed by it.
func (s *Server) WithNetAuth(credentials *netauth.Credentials, certs *netauth.ClientCerts) *Server {
	if credentials != nil {
		s.platformAuth = credentials
	}
	if certs != nil {
		s.clientCerts = certs
	}
	s.netAuthOnce.Do(s.initNetAuth)
	return s
}

// WithNetAuthRestoreNotes records why persisted client-certificate bindings could not be
// rebuilt at startup, so GET /api/network/client-certs can report them.
//
// The restore happens in cmd/burpsy, before this server exists, and its failures are the
// kind that must not be swallowed: a PKCS#12 file the operator deleted between sessions
// leaves a binding that was on the panel yesterday and will never be presented again.
// Carried here rather than logged and forgotten because the operator reading the panel is
// the person who can fix it, and they are not reading the log.
func (s *Server) WithNetAuthRestoreNotes(notes []string) *Server {
	s.netAuthRestoreNotes = notes
	return s
}

// organizerChanged mirrors the organizer and tells the live stream, and is what every organizer
// mutation calls instead of persisting directly.
//
// The organizer is notified from the handler rather than from a store hook — unlike traffic, findings
// and the tool log — because the handler is the only thing that ever mutates it. A hook inside a
// web-owned store would be a seam with one side. The case that makes the signal worth having is
// cross-tab: History's Save writes here, and before this the Organizer tab found out by being clicked.
func (s *Server) organizerChanged() {
	s.persistOrganizer()
	s.live.notify(changeOrganizer)
}

// WithSitemap replaces the site map, subscribing the new one to the store.
//
// Call before traffic flows. The map NewServer built stays subscribed — the store
// holds the only reference to its observer and there is no unsubscribe — so it
// keeps being fed while nothing reads it. That waste is bounded and silent, and
// the alternative (an unsubscribe protocol on the store) is more machinery than a
// replacement nothing currently performs is worth.
func (s *Server) WithSitemap(sm *sitemap.SiteMap) *Server {
	s.sitemap = sm
	sm.Follow(s.store)
	return s
}

// WithTasks attaches a shared task registry, so work started outside this package
// — a crawl, most importantly — appears on the same dashboard as the audits and
// attacks this server starts itself. Passing nil leaves the server's own registry
// in place rather than disabling the surface.
func (s *Server) WithTasks(reg *dash.Registry) *Server {
	if reg != nil {
		s.tasks = reg
		// The shared registry gets this server's event log, so tasks started elsewhere still produce
		// lifecycle events on the pane that shows them. Attaching rather than replacing the log means
		// the caller does not have to know the log exists to get this right.
		reg.WithEvents(s.events)
	}
	return s
}

// WithEvents attaches a shared event log, or nil to keep this server's own. Wired into the task
// registry as well, so lifecycle events land in the same log as everything else.
func (s *Server) WithEvents(log *dash.EventLog) *Server {
	if log != nil {
		s.events = log
		s.tasks.WithEvents(log)
		s.followLive()
	}
	return s
}

// Events returns the event log the process should record operator-visible actions into — the second
// seam the crawler is wired through, alongside Tasks.
func (s *Server) Events() *dash.EventLog { return s.events }

// Tasks returns the registry long-running work registers with. This is the seam
// the crawler is wired through: the process hands the same registry to both, and
// a crawl announces itself with one call — see the /api/dashboard docs.
func (s *Server) Tasks() *dash.Registry { return s.tasks }

// WithSessionCoordinator sets the session coordinator.
func (s *Server) WithSessionCoordinator(sc *session.Coordinator) *Server {
	s.sessionCoordinator = sc
	// The same jar, handed to the sender as the store a followed redirect chain replays from
	// (burpsy-react-ui-mr83). Without this a login performed by following a redirect lands in a jar
	// nothing else reads, so the Session page would not show the session the chain just established and
	// a later tool send would start from scratch.
	// The sender is mutated in place rather than replaced: the same *sender.Sender is already held by
	// every surface that was wired before this call, and handing one of them a copy would give the
	// jar to some sends and not others.
	if s.sender != nil {
		withSessionCookieJar(s.sender, sc)
	}
	// The jar's monitored-tool set (burpsy-react-ui-sn3j): the web layer's own absorbing
	// surfaces register here, the same wiring-time rule the proxy holds (it attaches itself in
	// WithCookieJar). The Repeater's sends, the Intruder's stored exemplars and the audit's
	// probe responses all reach this one coordinator, and Observation can then say which
	// surfaces are attached independent of which are switched on to absorb.
	sc.AttachAbsorptionSource(session.SourceRepeater)
	sc.AttachAbsorptionSource(session.SourceIntruder)
	sc.AttachAbsorptionSource(session.SourceScanner)
	s.installSuiteScopePredicate()
	// A rule's "Invoke an extension" action is wired here, beside the scope predicate and for the
	// same reason: the seam has match sites inside internal/session where no host is in reach, and a
	// rule that named an extension must not be reachable from one call path and refused from
	// another. The adapter resolves the host per call — see extension_session_action.go — so a plugin
	// loaded after this line is still found.
	s.sessionCoordinator.SetSessionActionInvoker(sessionActionInvoker{s: s})
	// The "Prompt the user for in-browser recovery" action is wired here for the same reason: a rule
	// that names the prompt must be reachable from every call path, and the console is the only
	// surface that can ask. See session_prompts.go.
	s.sessionCoordinator.SetSessionPrompter(sessionPrompter{s: s})
	return s
}

// installSuiteScopePredicate gives the session coordinator this console's live suite-scope verdict
// (7nh2), so a rule configured for "Use suite scope [defined in Target tab]" is matched against the
// Target scope as it stands at match time.
//
// Installed here rather than passed in at each call site because the session package has match
// sites of its own — HandleRecovery above all — where no scope handle is in reach, and a suite-mode
// rule must not be unreachable from any one of them. A caller that owns a scope (the proxy's, the
// crawler's, the CLI's) still passes its own predicate to MatchingRuleForRequest and that one wins.
//
// The closure reads s.scope and s.store's live scope state per request instead of capturing a copy:
// the Target tab rewrites the scope while rules exist, and a captured verdict is the divergence
// between what session handling matched and what the Scope tab shows.
func (s *Server) installSuiteScopePredicate() {
	if s.sessionCoordinator == nil {
		return
	}
	s.sessionCoordinator.SetSuiteScopePredicate(func(req session.RequestIdentity) bool {
		if s.scope == nil {
			// No Target scope handle at all, so there is no suite verdict to give. Refusing keeps
			// suite mode from collapsing into "everything" in a process that has no scope to
			// consult — the one reading that would fire a login macro at an arbitrary host.
			// (An empty *scope*, by contrast, is this codebase's documented default-allow and
			// answers true through Contains below, exactly as every other scope gate reads it.)
			return false
		}
		return s.scope.Contains(req.Host, req.Port, req.Path, req.TLS)
	})
}

// WithMatchReplace sets the match/replace rule set.
func (s *Server) WithMatchReplace(mr *matchreplace.RuleSet) *Server {
	s.matchReplace = mr
	return s
}

// WithToolLog sets the tool log.
func (s *Server) WithToolLog(tl *toollog.ToolLog) *Server {
	s.toolLog = tl
	// The capture filter's ScopeOnly axis is answered by the engagement scope, so the log needs a
	// reference to it. Without this the switch was accepted and stored and then filtered nothing
	// (burpsy-react-ui-72k9). Guarded: tests build servers with a nil scope, and a nil scope must
	// leave the switch inert rather than panic the constructor.
	if s.scope != nil {
		tl.SetScope(s.scope)
	}
	s.followLive()
	return s
}

func (s *Server) setupRoutes() {
	// Capture + stats
	s.mux.HandleFunc("/api/history", s.handleHistory)
	// Import HAR (eyi1): bring traffic captured elsewhere into history without re-proxying it live.
	s.mux.HandleFunc("/api/history/import/har", s.handleHistoryImportHar)
	// Custom extractor columns (burpsy-react-ui-28n8): the saved definitions, and their values for a
	// page of rows.
	s.mux.HandleFunc("/api/history/extractors", s.handleHistoryExtractors)
	s.mux.HandleFunc("/api/history/extract", s.handleHistoryExtract)
	s.mux.HandleFunc("/api/message/", s.handleMessage)
	// Burp's suite-wide Search dialog (vs9k): the one search that crosses tools, run over the
	// store because the history rows the console holds carry no bytes to search. See api_search.go.
	s.mux.HandleFunc("/api/search", s.handleSearch)
	s.mux.HandleFunc("/api/exchange/", s.handleExchange)
	s.mux.HandleFunc("/api/exchanges/", s.handleExchange) // legacy alias for /api/exchange/
	s.mux.HandleFunc("/api/stats", s.handleStats)
	// Not under /api: a browser is told to fetch this by URL, and the UI links to it as a download.
	// Matches the Rust route (crates/web/src/lib.rs) so the shipped frontend's CA link works unchanged.
	s.mux.HandleFunc("/ca.crt", s.handleCACert)
	// The operator's own CA — W6 #10. GET reports which CA signs; the import replaces it and empties
	// the leaf cache. See api_ca.go.
	s.mux.HandleFunc("/api/backup", s.handleBackup)
	// The automatic-backup setting — interval schedule and delete-on-clean-shutdown (jkvb). See
	// api_backup_config.go.
	s.mux.HandleFunc("/api/backup/config", s.handleBackupConfig)
	s.mux.HandleFunc("/api/headers/uninteresting", s.handleUninterestingHeaders)
	s.mux.HandleFunc("/api/proxy/ca", s.handleCAStatus)
	s.mux.HandleFunc("/api/proxy/ca/import", s.handleCAImport)
	s.mux.HandleFunc("/api/proxy/ca/regenerate", s.handleCARegenerate)
	// Burp's "Open browser" (burpsy-react-ui-bufa): a Chromium pre-wired to a live listener and pinned
	// to burpsy's CA, its settings, and Burp's "Clear all browser data". See api_browser.go.
	s.mux.HandleFunc("/api/browser/launch", s.handleBrowserLaunch)
	s.mux.HandleFunc("/api/browser/settings", s.handleBrowserSettings)
	s.mux.HandleFunc("/api/browser/clear", s.handleBrowserClear)
	// Export the CA certificate, private key or a PKCS#12 pair (burpsy-react-ui-j92x) so another tool
	// can intercept with the same CA. Behind the confirmation gate: see api_ca_export.go.
	s.mux.HandleFunc("/api/proxy/ca/export", s.handleCAExport)
	s.mux.HandleFunc("/api/scope", s.handleScope)
	s.mux.HandleFunc("/api/scanner/config", s.handleScannerConfig)
	s.mux.HandleFunc("/api/config/export", s.handleConfigExport)
	s.mux.HandleFunc("/api/config/import", s.handleConfigImport)
	s.mux.HandleFunc("/api/issues", s.handleIssues)
	// Record an issue (burpsy-react-ui-4qqz): the operator's hand-recorded finding, attached to
	// one exchange. ServeMux resolves the subtree /api/issues/{id} longest-prefix, so 'record'
	// would be swallowed by the id path if it matched an id shape — it does not (it is not
	// numeric), but registering it explicitly keeps handleIssueByID's numeric-only guard honest.
	s.mux.HandleFunc("/api/issues/record", s.handleIssueRecord)
	s.mux.HandleFunc("/api/issues/consolidation", s.handleIssueConsolidation)
	s.mux.HandleFunc("/api/scanner/secrets", s.handleScannerSecrets)
	s.mux.HandleFunc("/api/dominvader", s.handleDomInvader)
	s.mux.HandleFunc("/api/dominvader/hit", s.handleDomInvaderHit)
	s.mux.HandleFunc("/api/dominvader/hits", s.handleDomInvaderHits)
	s.mux.HandleFunc("/api/protobuf/decode", s.handleProtobufDecode)
	s.mux.HandleFunc("/api/protobuf/encode", s.handleProtobufEncode)
	s.mux.HandleFunc("/api/authz/identities", s.handleAuthzIdentities)
	s.mux.HandleFunc("/api/authz/test", s.handleAuthzTest)
	// The write path for the same resource: operator triage and delete, per finding. Registered as a
	// subtree because "/api/issues" above takes the exact match; ServeMux resolves /api/issues/{id}
	// here without ambiguity.
	s.mux.HandleFunc("/api/issues/", s.handleIssueByID)
	// The LLM second look (ei0v): the pass over gated findings, and its settings door. The
	// /api/issues/triage exact pattern outranks the {id} subtree above it, so "triage" is
	// never mistaken for an issue id.
	s.mux.HandleFunc("/api/issues/triage", s.handleIssueTriageRun)
	s.mux.HandleFunc("/api/settings/triage", s.handleTriageSettings)
	s.mux.HandleFunc("/api/findings", s.handleFindings) // legacy alias for /api/issues
	// The issue-definition catalogue, independent of whether anything was found. Two patterns because
	// they are two operations on two shapes: the exact path lists index rows, the subtree serves one
	// definition in full. ServeMux picks the longest match regardless of registration order.
	s.mux.HandleFunc("/api/advisories", s.handleAdvisories)
	s.mux.HandleFunc("/api/advisories/", s.handleAdvisoryDetail)
	// Engagement tools over the site map (burpsy-react-ui-1s07): Find comments, Find scripts
	// and Find references, Burp's three site-map searches, computed over stored responses.
	// One subtree pattern because the kind IS the path's last segment.
	s.mux.HandleFunc("/api/engagement/", s.handleEngagement)
	s.mux.HandleFunc("/api/engagement/clickbandit.js", s.handleClickbandit)
	s.mux.HandleFunc("/api/target/analyze", s.handleTargetAnalyze)
	// "Show response in browser" (burpsy-react-ui-js5y): the stored response replayed at a
	// stable URL, riding the exchange subtree like /csrf. See api_inbrowser.go.
	s.mux.HandleFunc("/api/exchange/in-browser/", s.handleExchangeInBrowserByID)

	// Tools
	s.mux.HandleFunc("/api/repeater/send", s.handleRepeaterSend)
	s.mux.HandleFunc("/api/repeater/ws-send", s.handleRepeaterWsSend)
	s.mux.HandleFunc("/api/repeater/browser-reissue", s.handleRepeaterBrowserReissue)
	// The re-issue fetch is served outside /api on purpose: it is the URL the operator's
	// browser opens, and a URL the operator types should not look like a console API route.
	// It is registered last so it cannot shadow an /api path, and its handler spends a token
	// before anything else, so nothing here is reachable without one (burpsy-react-ui-7rk0).
	s.mux.HandleFunc("/reissue/", s.handleBrowserReissueFetch)
	// Send a whole tab group: in tab order on one shared socket, in tab order on separate
	// connections, or all at once. See api_repeater_group.go — the shared-socket mode is the first
	// caller sender's keep-alive primitive has ever had outside its own tests, and it is what makes a
	// smuggling or desync test performable from Repeater at all.
	s.mux.HandleFunc("/api/repeater/send-group", s.handleRepeaterSendGroup)
	// Which protocol this tool's own traffic actually used, and a send path for a deliberately malformed
	// frame program. See api_protocol.go: both are capabilities that existed and had no route to an
	// operator.
	s.mux.HandleFunc("/api/protocols", s.handleProtocols)
	// The Project menu's two reads (burpsy-react-ui-je3y): which project this instance is —
	// name, -db path, whether anything is durable at all — and the name's write. Burp has a
	// whole Project container; burpsy's project IS the database file, so the readout names the
	// file and the menu's other items hang off what it reports.
	s.mux.HandleFunc("/api/project", s.handleProject)
	s.mux.HandleFunc("/api/project/name", s.handleProjectName)
	// In-console open/switch (burpsy-react-ui-dlw2): the front half je3y had to decline. The switch
	// re-runs the one-time restore against the new file and re-points every sink — see
	// api_project_open.go for why it is not a pointer swap.
	s.mux.HandleFunc("/api/project/open", s.handleProjectOpen)
	s.mux.HandleFunc("/api/projects", s.handleProjectList)
	s.mux.HandleFunc("/api/http2/program", s.handleHTTP2Program)
	s.mux.HandleFunc("/api/intruder/points", s.handleIntruderPoints)
	s.mux.HandleFunc("/api/intruder/run", s.handleIntruderRun)
	// Reaching a *running* attack. Two patterns because they are two shapes: the exact path lists what
	// is running, the prefix carries the per-attack action. Before these an attack could not be paused,
	// resumed or stopped from anywhere — see api_intruder_control.go.
	s.mux.HandleFunc("/api/intruder/attacks", s.handleIntruderAttacks)
	s.mux.HandleFunc("/api/intruder/attacks/", s.handleIntruderAttackAction)
	s.mux.HandleFunc("/api/scanner/live", s.handleScannerLive)
	s.mux.HandleFunc("/api/scanner/coverage", s.handleScannerCoverage)
	// The Custom scan checks leaf (burpsy-react-ui-kdqj): the corpus as rows, and the per-row switch
	// the audit engine reads.
	s.mux.HandleFunc("/api/scanner/checks", s.handleCorpusChecks)
	s.mux.HandleFunc("/api/scanner/checks/enable", s.handleCorpusCheckEnable)
	// Console authoring of custom scan checks (kbu1): Validate, Import, source (Export/Delete), Reload, Run test.
	s.mux.HandleFunc("/api/scanner/checks/validate", s.handleCheckValidate)
	s.mux.HandleFunc("/api/scanner/checks/import", s.handleCheckImport)
	s.mux.HandleFunc("/api/scanner/checks/source", s.handleCheckSource)
	s.mux.HandleFunc("/api/scanner/checks/reload", s.handleCheckReload)
	s.mux.HandleFunc("/api/scanner/checks/test", s.handleCheckTest)
	s.mux.HandleFunc("/api/scanner/configs", s.handleScannerConfigs)
	// The catalogue the per-issue selection is chosen from, by name, with each type's detection
	// methods and which of them burpsy runs (burpsy-react-ui-saq3.3.1).
	s.mux.HandleFunc("/api/scanner/issue-types", s.handleScannerIssueTypes)
	s.mux.HandleFunc("/api/scanner/audit", s.handleScannerAudit) // legacy alias for /api/audit/{id}
	// The audit queue, and the one action on a queued item. Two patterns because they are two
	// operations on two shapes: the exact path lists the queue, the subtree acts on one item. Note the
	// exact pattern above does *not* swallow these — a ServeMux pattern without a trailing slash
	// matches that path and nothing else, so "/api/scanner/audit" and "/api/scanner/audit-items" are
	// unrelated routes despite the shared prefix.
	s.mux.HandleFunc("/api/scanner/audit-items", s.handleScannerAuditItems)
	s.mux.HandleFunc("/api/scanner/audit-items/", s.handleScannerAuditItemAction)
	// Registered as a literal pattern as well as living under the /api/audit/ subtree: net/http's mux
	// prefers the more specific pattern, so this wins over the subtree and does not have to be special
	// cased inside handleAuditByPath — where a bare ParseUint failure on "selected" would answer 400
	// "Invalid exchange id" for a request that names no id at all.
	s.mux.HandleFunc("/api/audit/selected", s.handleAuditSelected)
	s.mux.HandleFunc("/api/audit/", s.handleAuditByPath)
	s.mux.HandleFunc("/api/sequencer/analyse", s.handleSequencerAnalyse)
	// Burp's Sequencer Analysis Settings — the ten sequencer.* keys (burpsy-react-ui-nm81).
	s.mux.HandleFunc("/api/sequencer/settings", s.handleSequencerSettings)
	// Two patterns, because they are two operations: the exact path starts a capture, the subtree
	// reads one and stops one. Registered exact-first for readability only — ServeMux picks the
	// longest matching pattern regardless of registration order.
	s.mux.HandleFunc("/api/sequencer/capture", s.handleSequencerCaptureStart)
	s.mux.HandleFunc("/api/sequencer/capture/", s.handleSequencerCapture)

	// Collaborator: the out-of-band interaction channel. Five routes rather than one because the
	// index/detail split applies here too — the table is rows, and an interaction's raw bytes are
	// fetched per row. `status` and `poll` are the same shape deliberately: the difference between them
	// is only whether the operator asked for the read now, and a caller should not have to reconcile
	// two views of one channel. See api_collaborator.go on why none of the GETs can register a channel.
	s.mux.HandleFunc("/api/collaborator/interaction/", s.handleCollaboratorInteraction)
	// The intruder payload upload (016): an operator's wordlist arrives as the body and lands
	// in burpsy's upload directory; the response names the path the ordinary file payload
	// source resolves. A POST because it stores state.
	s.mux.HandleFunc("/api/intruder/payload-files", s.handleIntruderPayloadUpload)
	// The wordlist manager (kal): the one inventory of payload corpora — bundled and
	// uploaded — so Intruder's file source and content discovery both point once.
	s.mux.HandleFunc("/api/wordlists", s.handleWordlists)
	// Burp's "Run health check" (8e3n). Like /payload it may register the channel: an explicit click.
	s.mux.HandleFunc("/api/collaborator/health", s.handleCollaboratorHealth)
	s.mux.HandleFunc("/api/collaborator/interactions", s.handleCollaboratorInteractions)
	s.mux.HandleFunc("/api/collaborator/payload", s.handleCollaboratorPayload)
	s.mux.HandleFunc("/api/collaborator/poll", s.handleCollaboratorPoll)
	// The one collaborator route that changes state: it installs a provider. Refuses once a channel
	// has registered a domain — see handleCollaboratorServer.
	s.mux.HandleFunc("/api/collaborator/server", s.handleCollaboratorServer)
	s.mux.HandleFunc("/api/collaborator/status", s.handleCollaboratorStatus)

	// Session
	s.mux.HandleFunc("/api/session/rules", s.handleSessionRules)
	s.mux.HandleFunc("/api/session/rules/", s.handleSessionRuleDetail)
	s.mux.HandleFunc("/api/session/cookies", s.handleSessionCookies)
	// The session-handling tracer (burpsy-react-ui-n29): one subtree serving the entries and
	// the enable toggle, the same one-door shape the jar's reads and writes hold.
	s.mux.HandleFunc("/api/session/trace", s.handleSessionTrace)
	s.mux.HandleFunc("/api/session/trace/enable", s.handleSessionTrace)
	s.mux.HandleFunc("/api/session/login", s.handleSessionLogin)
	// The macro recorder: turns selected Proxy-history rows into macro steps (burpsy-react-ui-escl).
	// Bare POST, under /api/session/ but deliberately not under /api/session/rules/: it neither reads
	// nor writes a rule, it converts messages, and parking it under the rules subtree would make it
	// inherit the credential risk class it does not deserve.
	s.mux.HandleFunc("/api/session/macro-steps", s.handleSessionMacroSteps)
	// The browser-recovery prompt registry (burpsy-react-ui-dq1g): the exact pattern reads the
	// pending list, the subtree resolves one. A task blocked on the prompt waits on the seam until
	// the operator answers here — see session_prompts.go.
	s.mux.HandleFunc("/api/session/prompts", s.handleSessionPrompts)
	s.mux.HandleFunc("/api/session/prompts/", s.handleSessionPromptResolve)

	// Network: platform authentication and client TLS certificates. Neither route ever
	// serves a secret — see api_network.go.
	s.mux.HandleFunc("/api/network/auth", s.handleNetworkAuth)
	s.mux.HandleFunc("/api/network/client-certs", s.handleNetworkClientCerts)

	// Intercept (condition lists + held queue)
	s.mux.HandleFunc("/api/intercept", s.handleIntercept)
	s.mux.HandleFunc("/api/proxy/passthrough", s.handleTlsPassthrough)
	s.mux.HandleFunc("/api/proxy/options", s.handleProxyOptions)
	s.mux.HandleFunc("/api/proxy/listener", s.handleProxyListener)

	// Network settings — resolution, timeouts, redirects, 100-continue, open-ended responses. Not
	// under /api/proxy/: these bind the sender every request-originating surface sends through, so a
	// name suggesting they were the proxy's would be wrong about who obeys them.
	s.mux.HandleFunc("/api/network/settings", s.handleNetworkSettings)

	// Named resource pools and scheduled tasks: Burp's configPanelResourcePools and
	// configPanelScheduledTasks. Two patterns each, for the reason the session-rule and audit-item
	// routes have two: the exact path is the collection (list, create) and the subtree is one object
	// by name (replace, delete). A name is operator prose and reaches the URL percent-encoded — see
	// pathName.
	s.mux.HandleFunc("/api/pools", s.handlePools)
	s.mux.HandleFunc("/api/pools/", s.handlePoolDetail)
	s.mux.HandleFunc("/api/schedules", s.handleSchedules)
	s.mux.HandleFunc("/api/schedules/", s.handleScheduleDetail)
	s.mux.HandleFunc("/api/intercept/enable", s.handleInterceptEnable)
	s.mux.HandleFunc("/api/intercept/in-scope-only", s.handleInterceptInScopeOnly)

	// Burp's two newline corrections for an EDITED interception (80tg). riskLocal: they rewrite the
	// bytes the operator is about to send, and the whole point of the feature is that the operator
	// chose to. The wire route above is the same shape, so this one is classified the same way.
	s.mux.HandleFunc("/api/intercept/newline-correction", s.handleInterceptNewlineCorrection)
	s.mux.HandleFunc("/api/scanner/passive-branch", s.handlePassiveBranch)
	s.mux.HandleFunc("/api/intercept/forward-all", s.handleInterceptForwardAll)
	s.mux.HandleFunc("/api/intercept/drop-all", s.handleInterceptDropAll)
	s.mux.HandleFunc("/api/intercept/rules/", s.handleInterceptRules)
	// The held queue's annotate write: /api/intercept/annotate/{id}, its own exact-subtree
	// handler. "annotate" is not an id shape, so it cannot collide with the held queue's
	// /api/intercept/{id} resolution paths below.
	s.mux.HandleFunc("/api/intercept/annotate/", s.handleInterceptAnnotate)
	// The startup preference (burpsy-react-ui-7vy): what the intercept switch reads at server
	// start. GET answers it; POST writes it. Its own route rather than a field on /enable for
	// the same reason in-scope-only has one — an endpoint named "enable" that also carried a
	// startup preference would let a caller set one and silently send the other.
	s.mux.HandleFunc("/api/intercept/startup", s.handleInterceptStartup)
	s.mux.HandleFunc("/api/intercept/", s.handleInterceptHeld)

	// Network: the upstream proxy / SOCKS chain every egress path follows (Unit 9).
	s.mux.HandleFunc("/api/network/proxy", s.handleNetworkProxy)

	// Site map
	s.mux.HandleFunc("/api/sitemap", s.handleSitemap)
	s.mux.HandleFunc("/api/tasks/", s.handleTaskCancel)
	s.mux.HandleFunc("/api/crawl", s.handleCrawl)
	// The fourth scan kind's door. Unlike /api/crawl it answers POST only: a run started here is
	// retained in the same registry the crawls are, so GET /api/crawl?task=N reads it back — see
	// api_apiscan.go's package comment for why there is one read door and not two.
	s.mux.HandleFunc("/api/apiscan", s.handleAPIScan)
	// Content discovery: Burp's "Discover content" engagement tool, delegated to ffuf. Registered
	// beside the crawl because they answer the same operator question from opposite ends — a crawl
	// follows what the application links to, a sweep guesses what it does not.
	s.mux.HandleFunc("/api/discovery", s.handleDiscovery)
	// Hidden-input guessing: Burp's Param Miner "Guess params", built in (burpsy-react-ui-wlz8). The
	// other half of the same question — discovery guesses paths, this guesses the inputs one path reads.
	s.mux.HandleFunc("/api/hidden-inputs", s.handleHiddenInputs)

	// The blind-XSS callback channel: the listener's state, and minting a correlation payload to plant.
	// Two patterns because they are two operations, and the mint is a POST because it changes what the
	// listener will answer for.
	s.mux.HandleFunc("/api/blindxss", s.handleBlindXSS)
	s.mux.HandleFunc("/api/blindxss/payload", s.handleBlindXSSPayload)

	// Dashboard: running tasks, the activity log, and every summary count with its
	// found/skipped/errored/gated breakdown.
	s.mux.HandleFunc("/api/dashboard", s.handleDashboard)
	// DELETE clears the event log the dashboard reads (Burp's "Clear event log"). Its own route, not
	// a verb on /api/dashboard, so a DELETE names the one list it discards rather than the aggregate.
	s.mux.HandleFunc("/api/dashboard/events", s.handleDashboardEvents)

	// Live change events: the stream that replaced the UI's polling, plus its own honest counters.
	s.mux.HandleFunc("/api/events", s.handleEvents)
	s.mux.HandleFunc("/api/events/stats", s.handleEventsStats)

	// Match & Replace + tool log + decoder/comparer/organizer
	s.mux.HandleFunc("/api/tools/rules", s.handleMatchReplaceRules)
	s.mux.HandleFunc("/api/tools/rules/test", s.handleMatchReplaceTest)
	s.mux.HandleFunc("/api/tools/log", s.handleToolLog)
	s.mux.HandleFunc("/api/tools/decode", s.handleToolsDecode)
	s.mux.HandleFunc("/api/tools/encode", s.handleToolsEncode)
	s.mux.HandleFunc("/api/tools/hash", s.handleToolsHash)
	s.mux.HandleFunc("/api/tools/compare", s.handleToolsCompare)
	// Compare site maps (burpsy-react-ui-k3a7): the path-set diff between two runs. Registered
	// beside the byte Comparer because it is the same engagement decision — "what changed between
	// these two things I captured" — at site-map granularity.
	s.mux.HandleFunc("/api/tools/compare-sitemaps", s.handleToolsCompareSitemaps)
	// PATCH /api/tools/log/{id} — the log comment/highlight write path. Registered as a subtree
	// because "/api/tools/log" above takes the exact match; without this line toolLogSetComment was
	// defined, declared in the manifest and reachable by nothing (burpsy-react-ui-5da).
	s.mux.HandleFunc("/api/tools/log/", s.toolLogSetComment)
	s.mux.HandleFunc("/api/tools/organizer", s.handleOrganizer)
	// Collections before the item subtree: ServeMux prefers the longer pattern, so /collections and
	// /collections/{id}/... reach handleOrganizerCollections while /{id} still reaches the item
	// handler. Registering only the item subtree is what made every collections call answer
	// "Invalid item id" (burpsy-react-ui-dcr).
	s.mux.HandleFunc("/api/tools/organizer/collections", s.handleOrganizerCollections)
	s.mux.HandleFunc("/api/tools/organizer/collections/", s.handleOrganizerCollections)
	s.mux.HandleFunc("/api/tools/organizer/", s.handleOrganizerItem)

	// WebSocket capture surface. The parenthetical here used to read "empty while the Go proxy has no
	// WS relay", which stopped being true when internal/proxy/ws.go landed: handleWebSocketUpgrade
	// and relayWebsocket relay frames in both directions and record them through wsCapture, so these
	// routes serve real captures. An operator who read the comment would have concluded that an empty
	// WebSockets history meant "unimplemented" rather than "no WebSocket traffic yet" — the same
	// misreading in the opposite direction from the honesty defects this phase is clearing.
	//
	// What is still partial is interception and edit-and-resend of frames (WS-02), which is Phase 6.
	s.mux.HandleFunc("/api/ws/connections", s.handleWSConnections)
	s.mux.HandleFunc("/api/ws/history", s.handleWSHistory)
	s.mux.HandleFunc("/api/ws/message/", s.handleWSMessage)

	// Extender: the plugin host. Six exact patterns rather than one subtree — see api_extensions.go for
	// why, and for why there is no BApp Store route.
	s.mux.HandleFunc("/api/extensions", s.handleExtensions)
	s.mux.HandleFunc("/api/extensions/apis", s.handleExtensionAPIs)
	s.mux.HandleFunc("/api/extensions/console", s.handleExtensionConsole)
	s.mux.HandleFunc("/api/extensions/invoke", s.handleExtensionInvoke)
	s.mux.HandleFunc("/api/extensions/load", s.handleExtensionLoad)
	s.mux.HandleFunc("/api/extensions/order", s.handleExtensionOrder)
	s.mux.HandleFunc("/api/extensions/unload", s.handleExtensionUnload)

	// Scanner report export: /api/report/{json|sarif|html}
	s.mux.HandleFunc("/api/report/", s.handleReport)

	// UI route
	s.mux.HandleFunc("/", s.handleUI)

	// The cross-site gate, installed over the finished mux (burpsy-react-ui-s19k). LAST, so it wraps
	// every route above and a route added after this line cannot be registered outside it — which is
	// the failure mode a per-handler check would have, and the reason a new handler's author has to
	// remember nothing.
	//
	// Here rather than in ListenAndServe because every test in this package drives s.mux.ServeHTTP
	// directly: a gate in the listener would be exercised by nothing and verified by nothing, and a
	// security control the suite cannot see is a comment rather than a control.
	// The unattended-caller gate (burpsy-react-ui-ejp5), inside the cross-site gate. Order matters:
	// sameOrigin first because a cross-site request should be refused for being cross-site whatever
	// it was trying to do, and the confirmation gate is a different question about a different kind
	// of caller.
	// The confirmation gate, and the cross-site gate it sits inside. Order is the whole argument:
	// sameOrigin is the OUTER one, so a cross-site request is refused for being cross-site and never
	// reaches the authorisation check at all. In the other order a cross-site caller got a 428
	// naming the route and the header to try — which tells an attacker probing the control exactly
	// what to send next, and means a request from a hostile page got as far as asking for
	// permission.
	//
	// s.registerConfirmationRoutes is called from here but lives in confirm_gate.go, because the
	// mint patterns are DERIVED from the manifest and the route-manifest test refuses a
	// non-literal HandleFunc argument in this file. The test is right to refuse it: a variable
	// pattern is invisible to the manifest. The mint endpoints are not manifest routes — they are
	// served by a separate mux and deliberately outside the manifest's remit — so the honest fix is
	// to keep them out of this file rather than to weaken the test.
	s.confirmMux = s.registerConfirmationRoutes()
	s.guarded = s.sameOriginOnly(s.confirmationGate(s.mux, s.confirmMux))
}

// gatedRoutePatterns is every manifest pattern whose risk class needs confirmation.
//
// Derived from the manifest rather than listed, because a list is a second statement of the policy
// and this file already exists to make the gate one derivation. The `/` root is excluded because it
// is an asset route and a subtree confirm endpoint under it would shadow every other pattern.
func gatedRoutePatterns() []string {
	var out []string
	for pattern, r := range manifest {
		if pattern == "/" || !needsConfirmation(r.risk) {
			continue
		}
		// A subtree pattern (trailing slash) already matches, so its own path is reachable through
		// it. An exact pattern is not, and the gate resolves it as written.
		out = append(out, pattern)
	}
	sort.Strings(out)
	return out
}

// sameOriginOnly wraps h so a mutating request that did not come from this console is refused.
//
// The name says what it does and the body says why: the console has no authentication, it is a tool
// that sends attacks, and it binds to loopback — which stops other hosts and not the operator's own
// browser, which visits hostile targets all day. See api_sameorigin.go for the three checks, the
// rebinding case each one covers, and the token that is deliberately not implemented here.
func (s *Server) sameOriginOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.requireSameOrigin(w, r) {
			return
		}
		h.ServeHTTP(w, r)
	})
}

// WithAllowedHosts names the Host header values this console answers to for mutating requests.
//
// Required for a non-loopback bind: `-web 0.0.0.0:8081` puts the console on the network, and a
// cross-site gate that only accepts loopback would refuse the operator's own browser along with
// everything else. Naming the address is the deliberate step; not naming it keeps the default, which
// is the safe one.
func (s *Server) WithAllowedHosts(hosts ...string) *Server {
	if s.allowedHosts == nil {
		s.allowedHosts = make(map[string]bool, len(hosts))
	}
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			s.allowedHosts[h] = true
		}
	}
	return s
}

// ListenAndServe starts the web server.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	// Remember the bound address so the DOM auditor can tell its extension where to report
	// (burpsy-react-ui-wl94). A wildcard or empty host is normalised to loopback by domInvaderReportURL.
	s.webAddr = addr
	// Cap every request body so a single oversized POST cannot exhaust memory.
	// The API is operator-facing and loopback-bound, but a body limit is cheap
	// insurance and the right default for any server that reads JSON into structs.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		s.guarded.ServeHTTP(w, r)
	})
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	// The clock starts here and not in NewServer, deliberately: a Server built directly — which every
	// test in this package does — must have no ticker, so no schedule can fire behind a test's back
	// and every schedule test drives Tick at an instant it chose. It also ties the scheduler's
	// lifetime to the serving lifetime, so a shutdown stops it with everything else rather than
	// leaving a goroutine starting audits against a process that is closing.
	go s.runScheduler(ctx, schedule.DefaultResolution)

	s.logger.Info("web server listening", zap.String("addr", addr))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	// Serve the static web UI, embedded at build time.
	uiHandler(w, r)
}

// loadAdvisories loads the issue-definition catalogue, or returns nil.
//
// Nil rather than an error, and no log line at construction: a server that cannot enrich findings is
// still a working server, and NewServer has no logger yet at the point this runs. The consequence is
// visible where it matters instead — GET /api/issues reports the catalogue size, so an operator
// seeing plain findings can tell "no catalogue loaded" from "this check has no definition".
func loadAdvisories() *advisory.Catalogue {
	c, err := advisory.Load()
	if err != nil {
		return nil
	}
	return c
}
