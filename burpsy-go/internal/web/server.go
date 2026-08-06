package web

import (
	"context"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/advisory"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/organizer"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/sitemap"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"go.uber.org/zap"
)

// Server represents the web API server.
type Server struct {
	store          *core.TrafficStore
	scope          *core.Scope
	logger         *zap.Logger
	mux            *http.ServeMux
	sender         *sender.Sender
	scanner        *scanner.ActiveScanner
	passiveScanner *scanner.PassiveScanner
	findings       *core.FindingStore
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
	liveAudit          *LiveAuditState
	tasks              *dash.Registry
	// crawls retains recent crawl reports, keyed by the task id that produced them, so the dashboard
	// row and the coverage report are one identity rather than two numbers to correlate by hand.
	crawls *crawlRuns
	// events is the DASH-02 event log: what the tool *did*, as opposed to toolLog's what-it-*sent*.
	// Two logs because they count different things — see internal/dash/events.go.
	events *dash.EventLog
	// caCertPEM is the CA certificate the proxy signs leaves with, served at /ca.crt so a browser can
	// be told to trust it. Nil when interception is off, and then the route reports that rather than
	// serving an empty file — see handleCACert.
	caCertPEM []byte
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
		toolLog:            toollog.New(),
		organizer:          organizer.New(),
		loginRuns:          newSessionLoginRuns(),
		intercept:          intercept.NewEngine(),
		tasks:              dash.NewRegistry(),
		crawls:             newCrawlRuns(),
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

// WithScanner sets the active scanner used by the audit endpoint.
func (s *Server) WithScanner(scan *scanner.ActiveScanner) *Server {
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

// WithIntercept attaches the shared intercept engine. The web API and the proxy
// must hold the same instance, or edits here would not affect the hold queue.
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
func (s *Server) WithCACertPEM(pem []byte) *Server {
	s.caCertPEM = pem
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

func (s *Server) persistOrganizer() {
	if s.persist != nil {
		s.persist.SaveOrganizer(s.organizer.List())
	}
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
	s.mux.HandleFunc("/api/scope", s.handleScope)
	s.mux.HandleFunc("/api/issues", s.handleIssues)
	s.mux.HandleFunc("/api/findings", s.handleFindings) // legacy alias for /api/issues

	// Tools
	s.mux.HandleFunc("/api/repeater/send", s.handleRepeaterSend)
	// Which protocol this tool's own traffic actually used, and a send path for a deliberately malformed
	// frame program. See api_protocol.go: both are capabilities that existed and had no route to an
	// operator.
	s.mux.HandleFunc("/api/protocols", s.handleProtocols)
	s.mux.HandleFunc("/api/http2/program", s.handleHTTP2Program)
	s.mux.HandleFunc("/api/intruder/points", s.handleIntruderPoints)
	s.mux.HandleFunc("/api/intruder/run", s.handleIntruderRun)
	s.mux.HandleFunc("/api/scanner/live", s.handleScannerLive)
	s.mux.HandleFunc("/api/scanner/coverage", s.handleScannerCoverage)
	s.mux.HandleFunc("/api/scanner/configs", s.handleScannerConfigs)
	s.mux.HandleFunc("/api/scanner/audit", s.handleScannerAudit) // legacy alias for /api/audit/{id}
	s.mux.HandleFunc("/api/audit/", s.handleAuditByPath)
	s.mux.HandleFunc("/api/sequencer/analyse", s.handleSequencerAnalyse)
	s.mux.HandleFunc("/api/sequencer/capture/", s.handleSequencerCapture)

	// Session
	s.mux.HandleFunc("/api/session/rules", s.handleSessionRules)
	s.mux.HandleFunc("/api/session/rules/", s.handleSessionRuleDetail)
	s.mux.HandleFunc("/api/session/cookies", s.handleSessionCookies)
	s.mux.HandleFunc("/api/session/login", s.handleSessionLogin)

	// Intercept (condition lists + held queue)
	s.mux.HandleFunc("/api/intercept", s.handleIntercept)
	s.mux.HandleFunc("/api/intercept/enable", s.handleInterceptEnable)
	s.mux.HandleFunc("/api/intercept/rules/", s.handleInterceptRules)
	s.mux.HandleFunc("/api/intercept/", s.handleInterceptHeld)

	// Site map
	s.mux.HandleFunc("/api/sitemap", s.handleSitemap)
	s.mux.HandleFunc("/api/crawl", s.handleCrawl)

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
	s.mux.HandleFunc("/api/tools/organizer", s.handleOrganizer)
	s.mux.HandleFunc("/api/tools/organizer/", s.handleOrganizerItem)

	// WebSocket capture surface (empty while the Go proxy has no WS relay)
	s.mux.HandleFunc("/api/ws/connections", s.handleWSConnections)
	s.mux.HandleFunc("/api/ws/history", s.handleWSHistory)
	s.mux.HandleFunc("/api/ws/message/", s.handleWSMessage)

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
