package web

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/burpsy-go/burpsy/internal/advisory"
	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
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
	// domEngine is the -dom flag value, reported by /api/stats. Empty means no engine was named.
	domEngine string
	// tlsInterception reports whether the server is configured for TLS
	// interception (determined by whether a CA cert PEM exists).
	tlsInterception bool
	mux             *http.ServeMux
	sender          *sender.Sender
	scanner         *scanner.ActiveScanner
	passiveScanner  *scanner.PassiveScanner
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
	matchReplace       *matchreplace.RuleSet
	toolLog            *toollog.ToolLog
	organizer          *organizer.Store
	loginRuns          *sessionLoginRuns
	intercept          *intercept.Engine
	persist            *persist.Store
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
	collaborator     *collaboratorHub
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
		intercept:          intercept.NewEngine(),
		auditItems:         scanner.NewAuditItemLedger(scanner.DefaultAuditItemCap),
		tasks:              dash.NewRegistry(),
		attacks:            newAttackRegistry(),
		pools:              pool.New(),
		schedules:          schedule.NewRunner(),
		crawls:             newCrawlRuns(),
		discoveries:        newDiscoveryRuns(),
		events:             dash.NewEventLog(),
		live:               newEventHub(),
	}
	// One wiring call gives every task in the process — including a crawl registered from outside this
	// package — a started and a finished event, without either side knowing about the other.
	s.tasks.WithEvents(s.events)
	// The site map subscribes to the store here rather than rebuilding itself when
	// the tab is opened — see the sitemap package docs (CRAWL-05). Constructed
	// before any traffic can arrive, which is the ordering ObserveExchanges needs.
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
	s.toolLog.OnChange(func() { s.live.notify(changeToolLog) })
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
		scan = scan.WithPace(pool.ContextPacer{})
	}
	s.scanner = scan
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
		s.toolLog.SetPersistenceSink(p.SaveToolLog)
		s.restorePools(p)
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
		s.persist.SaveMatchRules(s.matchReplace.Rules(), s.matchReplace.UpdateContentLength())
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
	return s
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
	s.mux.HandleFunc("/api/message/", s.handleMessage)
	s.mux.HandleFunc("/api/exchange/", s.handleExchange)
	s.mux.HandleFunc("/api/exchanges/", s.handleExchange) // legacy alias for /api/exchange/
	s.mux.HandleFunc("/api/stats", s.handleStats)
	// Not under /api: a browser is told to fetch this by URL, and the UI links to it as a download.
	// Matches the Rust route (crates/web/src/lib.rs) so the shipped frontend's CA link works unchanged.
	s.mux.HandleFunc("/ca.crt", s.handleCACert)
	// The operator's own CA — W6 #10. GET reports which CA signs; the import replaces it and empties
	// the leaf cache. See api_ca.go.
	s.mux.HandleFunc("/api/backup", s.handleBackup)
	s.mux.HandleFunc("/api/headers/uninteresting", s.handleUninterestingHeaders)
	s.mux.HandleFunc("/api/proxy/ca", s.handleCAStatus)
	s.mux.HandleFunc("/api/proxy/ca/import", s.handleCAImport)
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
	// The write path for the same resource: operator triage and delete, per finding. Registered as a
	// subtree because "/api/issues" above takes the exact match; ServeMux resolves /api/issues/{id}
	// here without ambiguity.
	s.mux.HandleFunc("/api/issues/", s.handleIssueByID)
	s.mux.HandleFunc("/api/findings", s.handleFindings) // legacy alias for /api/issues
	// The issue-definition catalogue, independent of whether anything was found. Two patterns because
	// they are two operations on two shapes: the exact path lists index rows, the subtree serves one
	// definition in full. ServeMux picks the longest match regardless of registration order.
	s.mux.HandleFunc("/api/advisories", s.handleAdvisories)
	s.mux.HandleFunc("/api/advisories/", s.handleAdvisoryDetail)

	// Tools
	s.mux.HandleFunc("/api/repeater/send", s.handleRepeaterSend)
	// Send a whole tab group: in tab order on one shared socket, in tab order on separate
	// connections, or all at once. See api_repeater_group.go — the shared-socket mode is the first
	// caller sender's keep-alive primitive has ever had outside its own tests, and it is what makes a
	// smuggling or desync test performable from Repeater at all.
	s.mux.HandleFunc("/api/repeater/send-group", s.handleRepeaterSendGroup)
	// Which protocol this tool's own traffic actually used, and a send path for a deliberately malformed
	// frame program. See api_protocol.go: both are capabilities that existed and had no route to an
	// operator.
	s.mux.HandleFunc("/api/protocols", s.handleProtocols)
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
	s.mux.HandleFunc("/api/scanner/configs", s.handleScannerConfigs)
	s.mux.HandleFunc("/api/scanner/audit", s.handleScannerAudit) // legacy alias for /api/audit/{id}
	// The audit queue, and the one action on a queued item. Two patterns because they are two
	// operations on two shapes: the exact path lists the queue, the subtree acts on one item. Note the
	// exact pattern above does *not* swallow these — a ServeMux pattern without a trailing slash
	// matches that path and nothing else, so "/api/scanner/audit" and "/api/scanner/audit-items" are
	// unrelated routes despite the shared prefix.
	s.mux.HandleFunc("/api/scanner/audit-items", s.handleScannerAuditItems)
	s.mux.HandleFunc("/api/scanner/audit-items/", s.handleScannerAuditItemAction)
	s.mux.HandleFunc("/api/audit/", s.handleAuditByPath)
	s.mux.HandleFunc("/api/sequencer/analyse", s.handleSequencerAnalyse)
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
	s.mux.HandleFunc("/api/session/login", s.handleSessionLogin)

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
	s.mux.HandleFunc("/api/scanner/passive-branch", s.handlePassiveBranch)
	s.mux.HandleFunc("/api/intercept/forward-all", s.handleInterceptForwardAll)
	s.mux.HandleFunc("/api/intercept/drop-all", s.handleInterceptDropAll)
	s.mux.HandleFunc("/api/intercept/rules/", s.handleInterceptRules)
	s.mux.HandleFunc("/api/intercept/", s.handleInterceptHeld)

	// Network: the upstream proxy / SOCKS chain every egress path follows (Unit 9).
	s.mux.HandleFunc("/api/network/proxy", s.handleNetworkProxy)

	// Site map
	s.mux.HandleFunc("/api/sitemap", s.handleSitemap)
	s.mux.HandleFunc("/api/tasks/", s.handleTaskCancel)
	s.mux.HandleFunc("/api/crawl", s.handleCrawl)
	// Content discovery: Burp's "Discover content" engagement tool, delegated to ffuf. Registered
	// beside the crawl because they answer the same operator question from opposite ends — a crawl
	// follows what the application links to, a sweep guesses what it does not.
	s.mux.HandleFunc("/api/discovery", s.handleDiscovery)

	// The blind-XSS callback channel: the listener's state, and minting a correlation payload to plant.
	// Two patterns because they are two operations, and the mint is a POST because it changes what the
	// listener will answer for.
	s.mux.HandleFunc("/api/blindxss", s.handleBlindXSS)
	s.mux.HandleFunc("/api/blindxss/payload", s.handleBlindXSSPayload)

	// Dashboard: running tasks, the activity log, and every summary count with its
	// found/skipped/errored/gated breakdown.
	s.mux.HandleFunc("/api/dashboard", s.handleDashboard)

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
	s.mux.HandleFunc("/api/extensions/unload", s.handleExtensionUnload)

	// Scanner report export: /api/report/{json|sarif|html}
	s.mux.HandleFunc("/api/report/", s.handleReport)

	// UI route
	s.mux.HandleFunc("/", s.handleUI)
}

// ListenAndServe starts the web server.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	// Cap every request body so a single oversized POST cannot exhaust memory.
	// The API is operator-facing and loopback-bound, but a body limit is cheap
	// insurance and the right default for any server that reads JSON into structs.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		s.mux.ServeHTTP(w, r)
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
