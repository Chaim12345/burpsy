package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/blindxss"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/extension"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/oob"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/web"
	"go.uber.org/zap"
)

func main() {
	// Parse flags
	proxyBind := flag.String("proxy", "127.0.0.1:8080", "proxy bind address")
	webBind := flag.String("web", "127.0.0.1:8081", "web UI bind address")
	captureDir := flag.String("capture-dir", "", "directory for segment-based capture")
	dbFile := flag.String("db", "", "SQLite database for persistent state (history, findings, scope, rules)")
	scopeInclude := flag.String("scope-include", "", "include host pattern in scope")
	scopeExclude := flag.String("scope-exclude", "", "exclude host pattern from scope")
	interceptTLS := flag.Bool("intercept-tls", false, "enable TLS interception")
	caDir := flag.String("ca-dir", proxy.DefaultCADir(), "CA certificate directory")
	segmentBytes := flag.Uint64("segment-bytes", core.DefaultSegmentTargetBytes, "target bytes per segment file")
	bchecksDir := flag.String("bchecks", "", "load PortSwigger BCheck files and passively scan responses")
	// Allowlist for the bcheck `run tool` statement: name=path pairs, comma-separated. A check
	// that invokes a tool not named here is refused — the same gate as the egress chokepoint.
	// Tool execution is operator policy because it runs arbitrary external binaries.
	// The same allowlist also gates `burpsy extscan`, which delegates a whole scan phase to ffuf or
	// nuclei rather than running a tool per insertion point. One flag, one policy decision.
	// The same allowlist also gates POST /api/discovery, which is `extscan`'s ffuf phase reached from
	// the console's site map instead of from the command line. One flag, one policy decision, whichever
	// surface asks.
	toolsFlag := flag.String("tools", "", "allowlist external tools for `run tool` bchecks, `extscan` and /api/discovery: sqlmap=/usr/bin/sqlmap,ffuf=ffuf,nuclei=nuclei (comma-separated name=path)")
	// The blind-XSS callback channel. Off unless an address is given, because binding a socket that a
	// third party's browser is expected to reach is an engagement decision and not a default: the
	// payload runs in a real person's session, and the only thing that justifies it is that somebody
	// deliberately set this up. With no address the /api/blindxss surface reports that it is unwired
	// rather than answering with an empty callback list.
	blindXSSBind := flag.String("blindxss", "", "bind a blind-XSS callback listener on this address (e.g. 0.0.0.0:8088); off when empty")
	blindXSSURL := flag.String("blindxss-url", "", "the externally reachable origin planted blind-XSS payloads load from, when it differs from -blindxss (e.g. http://collab.example.net:8088)")
	// Allowlist for the Extender: name=path pairs, comma-separated. A plugin is a local executable that
	// speaks newline-delimited JSON-RPC on its stdin and stdout; there is no registry and no store, so
	// this flag is the only way one is admitted. Nothing is started here — a load is an act the operator
	// performs from the Extensions tab — and a name that is not on this list cannot be loaded at all,
	// the same gate -tools puts in front of `run tool`.
	pluginsFlag := flag.String("plugins", "", "allowlist burpsy plugins for the Extender: name=/path/to/plugin (comma-separated name=path)")
	// SCAN-03: the shipped configurations were reachable from nothing. This sets the default every
	// audit this process runs uses; a per-audit override goes on the request body. "list" prints the
	// names and exits, because the names contain spaces and hyphens and guessing them is hopeless.
	scanConfig := flag.String("scan-config", "", `run audits under a built-in scan configuration by name ("list" prints them)`)
	// DOM execution is operator policy for the same reason -tools is: "chrome" launches a browser
	// process, and a ws:// endpoint hands page control to a server this process did not start.
	// Empty is the behaviour this binary had unconditionally until now — every DOM-based check
	// reports a missing capability rather than an empty observation set. One flag, three forms:
	// domexec refuses RemoteURL together with ChromePath as a contradiction, and a single flag
	// cannot express that pair at all.
	domEngine := flag.String("dom", "", `engine for DOM-based checks: "chrome", a browser path, or a ws:// CDP endpoint (obscura/lightpanda serve)`)

	// The out-of-band interaction channel, and the only way to turn it on.
	//
	// `internal/oob` and `scanner.NewLazyOOBProvider` were both implemented, tested, and reachable from
	// nothing: the provider had zero callers, so `ActiveScanner.oob` was nil in every running burpsy and
	// every out-of-band check refused with "no collaborator channel is configured for this scan". This
	// flag is what makes the capability exist for an operator.
	//
	// Opt-in, and deliberately not "on whenever interactsh-client happens to be installed". Registering
	// a payload domain reaches a third-party interaction server and tells it an engagement is running;
	// that is a decision for the person running the tool, not a side effect of what is on PATH. It is
	// the same reason -tools is opt-in: capabilities that leave the process are operator policy.
	//
	// "public" rather than an empty string for the default pool, because empty already means "not
	// configured" — and those two must not be spelled the same way when one of them mints addresses.
	collaboratorServer := flag.String("collaborator-server", "",
		`Interactsh server for out-of-band interactions, or "public" for interactsh's own pool. Unset disables the Collaborator tool`)
	collaboratorClient := flag.String("collaborator-client", "",
		"path to the interactsh-client binary (default: look it up on PATH)")

	// TLS passthrough flags
	passthrough := flag.String("tls-passthrough", "", "host pattern to passthrough without interception (repeatable)")
	passthroughPorts := flag.String("tls-passthrough-port", "", "port to passthrough without interception (repeatable)")
	passthroughDefaults := flag.Bool("tls-defaults", false, "preload common pinned hosts for passthrough")
	storeVerify := flag.String("store-verify", "", "verify a capture directory and exit")

	flag.Parse()

	// Before anything is built: this either prints a list and exits, or resolves a name, or refuses one
	// that does not exist. Resolving it late — after the proxy is listening — would mean a typo takes
	// the whole process down mid-engagement instead of at the command line.
	auditConfig, err := resolveScanConfig(*scanConfig)
	if err != nil {
		log.Fatal(err)
	}

	// Resolved here for the same reason: a -dom naming a binary that is not there fails at the
	// command line, where the operator is still looking, rather than at the first DOM check.
	domOpts, err := domEngineOptions(*domEngine)
	if err != nil {
		log.Fatal(err)
	}

	// CLI mode: when the first positional argument names a subcommand, drive the
	// engines directly (no HTTP) and exit. Global flags above still parse, so
	// `burpsy -db data.db history` reads the same database the proxy writes.
	if flag.NArg() > 0 {
		os.Exit(runCLI(flag.Arg(0), flag.Args()[1:], *captureDir, *segmentBytes, *scopeInclude, *scopeExclude, *dbFile, *bchecksDir, *toolsFlag, *domEngine))
	}

	// Handle store verify subcommand
	if *storeVerify != "" {
		fmt.Printf("Verifying capture directory: %s\n", *storeVerify)
		report := core.VerifyCaptureDir(*storeVerify)
		if len(report) == 0 {
			fmt.Printf("%s: no segments to check\n", *storeVerify)
			os.Exit(0)
		}
		records := 0
		var payload int64
		faults := 0
		for _, v := range report {
			records += v.Records
			payload += v.PayloadBytes
			if v.Fault != nil {
				// Dereferenced, not printed as a pointer: this used to print the
				// address of the fault string instead of the fault.
				faults++
				fmt.Printf("FAULT %s  %d record(s) checked, then: %s\n", v.Path, v.Records, *v.Fault)
			} else {
				fmt.Printf("ok    %s  %d record(s), %d payload byte(s)\n", v.Path, v.Records, v.PayloadBytes)
			}
		}
		fmt.Printf("\nchecked %d record(s) / %d payload byte(s) across %d segment(s), %d with faults\n",
			records, payload, len(report), faults)
		if faults > 0 {
			os.Exit(1)
		}
		os.Exit(0)
	}
	// Initialize logger
	logger, lerr := zap.NewProduction()
	if lerr != nil {
		// A logger is required for every subsystem below; fail fast rather than
		// dereference a nil *zap.Logger later.
		log.Fatalf("Failed to initialize logger: %v", lerr)
	}
	defer logger.Sync()

	// Create traffic store
	var store *core.TrafficStore
	if *captureDir != "" {
		store, err = core.NewTrafficStoreWithCaptureDir(*captureDir, *segmentBytes)
	} else {
		store = core.NewTrafficStore()
	}
	if err != nil {
		log.Fatalf("Failed to create traffic store: %v", err)
	}

	// Create scope
	scope := core.NewScope()
	if *scopeInclude != "" {
		scope.AddInclude(*scopeInclude)
	}
	if *scopeExclude != "" {
		scope.AddExclude(*scopeExclude)
	}

	// Create TLS policy
	tlsPolicy := proxy.NewTlsPolicy()
	if *interceptTLS {
		// Load or generate CA
		engine, err := proxy.LoadOrGenerateCA(*caDir)
		if err != nil {
			log.Fatalf("Failed to load/generate CA: %v", err)
		}
		tlsPolicy.WithEngine(engine)
	}

	// TLS passthrough defaults
	if *passthroughDefaults {
		tlsPolicy = proxy.NewTlsPolicy().WithCommonDefaults()
		// Re-apply engine if interceptTLS is also set
		if *interceptTLS {
			if engine, err := proxy.LoadOrGenerateCA(*caDir); err == nil {
				tlsPolicy.WithEngine(engine)
			}
		}
	}

	// Add passthrough patterns
	if *passthrough != "" {
		for _, p := range strings.Split(*passthrough, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				tlsPolicy.AddPassthrough(p)
			}
		}
	}

	// Add passthrough ports
	if *passthroughPorts != "" {
		for _, p := range strings.Split(*passthroughPorts, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				if port, err := strconv.Atoi(p); err == nil {
					tlsPolicy.AddPassthroughPort(uint16(port))
				}
			}
		}
	}

	// Shared finding store: passive scans (proxy) and active audits (web) both report here.
	findingStore := core.NewFindingStore()

	// Optional durable layer: -db makes SQLite the write-through mirror for
	// history, findings, scope and rules. Restore on startup, sink on mutation.
	var persistStore *persist.Store
	if *dbFile != "" {
		persistStore, err = persist.Open(*dbFile, logger)
		if err != nil {
			log.Fatalf("Failed to open database %s: %v", *dbFile, err)
		}
		defer persistStore.Close()
		// Tool log and coordinator are owned by the web server below, so restore
		// them after it exists; history/scope/findings restore here.
		if err := persistStore.Restore(store, findingStore, scope, nil, nil, nil, nil); err != nil {
			log.Fatalf("Failed to restore from database: %v", err)
		}
		store.SetPersistenceSinks(persistStore.SaveMessage, persistStore.SaveExchange)
		findingStore.SetPersistenceSink(persistStore.SaveFinding)
	}

	// Passive scanning is opt-in via --bchecks, mirroring the Rust CLI. Without
	// it the built-in header/cookie checks still run so existing tests keep their
	// expectations.
	var passiveScanner *scanner.PassiveScanner
	// The -tools allowlist becomes a runner only if something was configured. A
	// malformed entry is a construction error here, before any server starts —
	// a typo must not surface mid-scan as checks that silently cannot run.
	toolAllowlist, terr := parseToolAllowlist(*toolsFlag)
	if terr != nil {
		log.Fatal(terr)
	}
	var toolRunner bcheck.ToolRunner
	if toolAllowlist != nil {
		toolRunner = scanner.NewToolRunner(scanner.ToolRunnerConfig{Tools: toolAllowlist})
	}
	// The out-of-band provider, built only when the operator named a server. Lazy by construction:
	// nothing spawns interactsh-client until a check or the Collaborator tool actually asks for a
	// channel, so configuring one costs nothing on a run that never needs a callback.
	//
	// A missing binary is deliberately NOT fatal here, unlike the -tools typo above. -tools names a
	// path the operator typed, so a bad one is a command-line error; this names a server, and whether
	// interactsh-client can be found is a property of the machine that the provider reports honestly at
	// first use — as "unavailable", on the surface built to say so, rather than as a refusal to boot.
	var oobProvider scanner.OOBProvider
	if *collaboratorServer != "" {
		serverURL := *collaboratorServer
		if serverURL == "public" {
			// The client's own default pool. Empty ServerURL is what selects it.
			serverURL = ""
		}
		oobProvider = scanner.NewLazyOOBProvider(oob.Options{
			ServerURL:  serverURL,
			BinaryPath: *collaboratorClient,
		})
	}

	// One session coordinator for every surface that compares or edits session state — the same
	// single-handle rule as Scope: the web Session page's rules and the scanner's access-control
	// and CSRF comparisons must govern and be governed by one rule set. A copy would let the page
	// describe rules the scanner quietly stopped honouring.
	sessionCoord := session.NewCoordinator(logger)

	// The plugin host, built from -plugins for the same reason and at the same point as the tool
	// allowlist: a malformed entry must refuse to start rather than surface later as a plugin the
	// Extensions tab lists and cannot load. The host is always built, including with an empty
	// allowlist — that is what lets the tab say "nothing is allowlisted, here is the flag" instead of
	// reporting the feature as absent.
	pluginAllowlist, perr := parseNamePathAllowlist("-plugins", *pluginsFlag)
	if perr != nil {
		log.Fatal(perr)
	}
	pluginHost := extension.NewHost(extension.Config{Plugins: pluginSpecs(pluginAllowlist), Logger: logger})
	// Every child dies with this process. Deferred rather than left to the context cancel below because
	// Close asks each plugin to stop and waits for it, which the bare cancel does not.
	defer pluginHost.Close()
	if *bchecksDir != "" {
		ps, err := scanner.LoadDir(*bchecksDir, store, scope, logger)
		if err != nil {
			log.Fatalf("Failed to load BChecks from %s: %v", *bchecksDir, err)
		}
		passiveScanner = ps
		logger.Info("bchecks loaded", zap.String("dir", *bchecksDir), zap.String("report", ps.Report().Summary()))
		for i, e := range ps.Report().Errors {
			if i >= 5 {
				logger.Warn("more bcheck parse errors omitted", zap.Int("remaining", len(ps.Report().Errors)-5))
				break
			}
			logger.Warn("unparsable bcheck", zap.String("file", e.File), zap.String("error", e.Err))
		}
	} else {
		passiveScanner = scanner.NewPassiveScanner(store, logger)
	}

	// Create proxy config.
	//
	// The intercept engine and the match-and-replace rule set are both created here and handed to
	// *both* the proxy and the web server below, each as one shared object rather than a copy. This
	// is the same move the intercept engine already makes, and it is load-bearing for match & replace:
	// the Match & Replace page mutates this exact RuleSet through PUT /api/tools/rules, and the proxy
	// reads it on every request and response. Give the two sides separate RuleSets and the page would
	// render (and persist) a list the proxy had quietly stopped honouring — which was in fact the bug,
	// because the proxy's field was never set at all and every rule an operator edited was a
	// live-traffic no-op. WithMatchReplace on the web server (below) must run before WithPersist, so a
	// restored ruleset lands in this shared object.
	interceptEngine := intercept.NewEngine()
	matchReplaceRules := matchreplace.NewRuleSet()
	// The proxy's live option set — Burp's response-modification switches. One set handed to both
	// the relay and the web API, the same single-pointer rule as the TLS policy and the Match &
	// Replace rules: a panel that described a different set than the relay applies is the drift
	// this project keeps closing.
	proxyOptions := proxy.NewOptions()
	proxyConfig := proxy.NewProxyConfig(store).
		WithScope(scope).
		WithTlsPolicy(tlsPolicy).
		WithMatchReplace(matchReplaceRules).
		WithOptions(proxyOptions).
		WithLogger(logger).
		WithScanner(passiveScanner).
		WithFindings(findingStore).
		WithIntercept(interceptEngine)

	// Start proxy server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyServer := proxy.NewServer(proxyConfig)
	go func() {
		logger.Info("Starting proxy", zap.String("bind", *proxyBind))
		if err := proxyServer.ListenAndServe(ctx, *proxyBind); err != nil && err != context.Canceled {
			logger.Error("Proxy server failed", zap.Error(err))
		}
	}()

	// One sender for the scanner and the web server, where there were two.
	//
	// The two were a defect the network-settings surface made visible rather than caused. /api/network/settings
	// writes the sender the web server holds; with a second sender inside the scanner, a resolution
	// override an operator typed would have applied to Repeater and not to audit probes — a panel
	// claiming the whole process dials 10.0.0.1 while half of it still asked DNS. Sharing is also what
	// sender.go's own comment on the protocol cache asks for: "an intruder run and the scan that
	// preceded it share what either of them discovered". Sharing is safe because Sender guards its
	// config and client behind a mutex and its protocol cache is atomic.
	httpSender := sender.NewSender(sender.DefaultSenderConfig())

	// Persisted network settings apply before either consumer sends anything. Same precedence argument
	// as the scan-config restore below: what the operator set through the API in a previous run is a
	// later decision than this process's compiled-in defaults. A refusal is logged and the defaults
	// stand — a settings document that no longer validates must not stop the binary from starting, but
	// it must not be half-applied either, and ApplyNetwork is all-or-nothing.
	if persistStore != nil {
		saved, err := persistStore.LoadNetworkSettings()
		if err != nil {
			logger.Warn("Failed to load saved network settings; using defaults", zap.Error(err))
		} else if saved != nil {
			if err := httpSender.ApplyNetwork(*saved); err != nil {
				logger.Warn("Saved network settings were refused; using defaults", zap.Error(err))
			} else {
				logger.Info("Applied persisted network settings")
			}
		}
	}

	// Hoisted out of the builder chain below because the DOM engine is conditional: -dom names one,
	// and without it every DOM-based check reports a missing capability — which is what this binary
	// did unconditionally until the flag existed. The provider is lazy, so an audit whose check set
	// contains no DOM check never starts a browser.
	activeScanner := scanner.NewActiveScanner(store, logger).
		WithSender(httpSender).
		WithScope(scope).
		WithCorpusChecks(passiveScanner.ActiveChecks()).
		WithToolRunner(toolRunner).
		WithOOBProvider(oobProvider).
		// The capability handles this binary used to leave unwired: without the ledger the 10
		// stored/second-order checks refuse; without the coordinator, access-control and CSRF
		// refuse; without the JS/JWT checks those families refuse despite data compiled into the
		// binary. Each constructs unconditionally — the ledgers are in-memory and bounded, the JS
		// corpus is vendored and parsed once per process, the JWT wordlist is the compiled-in list.
		WithStoredLedger(scanner.NewStoredLedger()).
		WithProvenanceLedger(scanner.NewProvenanceLedger()).
		WithSessionCoordinator(sessionCoord).
		WithJsLibraryCheck(scanner.NewJsLibraryCheck(scanner.VendoredJsVulnDb())).
		WithJwtWeakSecretCheck(scanner.NewJwtWeakSecretCheck(scanner.BundledJwtWordlist())).
		WithAuditConfig(auditConfig)
	if domOpts != nil {
		activeScanner = activeScanner.WithBrowserProvider(scanner.NewLazyBrowserProvider(*domOpts))
	}

	// Persisted scan-config overrides apply last, after the flag chain: what the operator set
	// through /api/scanner/config in a previous run is a later decision than what this process was
	// launched with, and it must win. A database that never saved overrides leaves the flag-built
	// defaults untouched.
	if persistStore != nil {
		saved, err := persistStore.LoadScanConfig()
		if err != nil {
			logger.Warn("Failed to load saved scan configuration; using launch defaults", zap.Error(err))
		} else if saved != nil {
			activeScanner.UpdateScanConfig(func(c *scanner.ScanConfig) { *c = *saved })
			logger.Info("Applied persisted scan-configuration overrides")
		}
	}

	// The blind-XSS callback channel, bound before the web server so the API can report either the live
	// listener or the reason there is none. A bind failure is deliberately not fatal: everything else
	// this process does still works, and the honest outcome is a surface that says "no channel, because
	// X" rather than a refusal to start.
	blindXSSListener, blindXSSErr := startBlindXSS(ctx, *blindXSSBind, *blindXSSURL, logger)
	if blindXSSListener != nil {
		defer blindXSSListener.Close()
	}

	// Start web server
	webServer := web.NewServer(store, scope).
		WithLogger(logger).
		WithSender(httpSender).
		// WithScope is not optional here even though ActiveScanner treats it as such: without it this
		// scanner's probes are authorised against nothing, and this is the scanner every /api/audit call
		// uses. The web server only builds a scoped one of its own when none was attached, so leaving it
		// off here meant the flag-configured engagement scope silently did not apply to active probes.
		// WithAuditConfig carries -scan-config, so the endpoint's default is the one the operator named.
		// The active scanner dispatches the corpus's active checks (`given host/path/request` and
		// the insertion-point set) alongside the built-in table. The checks come from the same
		// LoadDir that built the passive scanner, so the two scanners can never disagree about
		// which corpus is loaded. ActiveChecks() is empty when no corpus was loaded, and
		// WithCorpusChecks leaves the built-in set alone then. WithToolRunner carries the -tools
		// allowlist, so a corpus check's `run tool` can dispatch; nil (no -tools) keeps tool
		// checks counted-but-excluded.
		WithScanner(activeScanner).
		// WithOOBProvider carries -collaborator-server. Installed on this scanner and only this one,
		// because it is the scanner the web server audits with — so the channel the Collaborator tab
		// displays and the channel a check plants in a payload are the same registration. Nil (no flag)
		// keeps every out-of-band row refusing rather than reporting zero interactions.
		WithPassiveScanner(passiveScanner).
		WithFindings(findingStore).
		WithIntercept(interceptEngine).
		// The same policy the proxy matches against, so Settings can list and edit
		// passthrough rules live: two copies would let the UI describe a list the
		// relay no longer obeys.
		WithTlsPolicy(tlsPolicy).
		// The same RuleSet the proxy config holds, so an edit on the Match & Replace page reaches
		// live traffic. Set before WithPersist (below) so a rule set restored from -db is loaded
		// into this shared object rather than one the proxy never sees.
		WithMatchReplace(matchReplaceRules).
		// The same session coordinator the scanner holds, so the Session page's rules and the
		// scanner's access-control/CSRF comparisons are one rule set. Without this the server
		// would quietly build its own no-op-logged coordinator and the two surfaces would drift.
		WithSessionCoordinator(sessionCoord).
		// The same option set the relay holds, so the Proxy settings panel's switches and the
		// response path's rules are one state.
		WithProxyOptions(proxyOptions).
		// The raw -tools map, for the surfaces that delegate a whole phase to an external binary rather
		// than one tool per insertion point: POST /api/discovery runs ffuf. Without -tools that route
		// refuses and names the missing tool, which is the difference between "not configured" and "this
		// target has nothing to find".
		WithExternalTools(toolAllowlist).
		// The blind-XSS callback channel, or the reason there is none. Both arguments carry information:
		// a bind failure must reach the API as a reason, because an endpoint that answered with an empty
		// callback list would be claiming it listened.
		WithBlindXSS(blindXSSListener, blindXSSErr).
		// The Extender's plugin host. Attached rather than built by the web server because which
		// executables may run is operator policy, exactly like -tools.
		WithExtensions(pluginHost).
		// So /ca.crt can serve it. Read here rather than in the web server because this is where the
		// CA directory is known. An unreadable file is a warning, not fatal: interception still works
		// for a client that already trusts the CA, and the operator gets told why the download is
		// missing instead of the link silently staying hidden.
		WithCACertPEM(readCACert(*interceptTLS, *caDir, logger)).
		WithBindAddrs(*proxyBind, *webBind).
		WithDOMEngine(*domEngine)
	if persistStore != nil {
		// Restore the web-owned stores (match & replace, session, organizer,
		// tool log) and mirror their tool activity.
		webServer.WithPersist(persistStore)
		// Runtime edits to the TLS passthrough list survive restarts. The persisted
		// patterns apply on top of whatever the flags configured — a flag rule and a
		// UI-added rule are both real rules, and dedupe keeps a pattern that arrived
		// by both doors from rendering twice in Settings.
		if patterns, err := persistStore.LoadTlsPassthrough(); err != nil {
			logger.Warn("could not restore TLS passthrough list", zap.Error(err))
		} else {
			existing := map[string]bool{}
			for _, p := range tlsPolicy.Passthrough() {
				existing[p] = true
			}
			for _, p := range patterns {
				if !existing[p] {
					tlsPolicy.AddPassthrough(p)
				}
			}
		}
	}
	// Live active audit: the sweep loop owns the context; cancelling ctx (on
	// shutdown) stops it at the next tick. It creates and wires the state if
	// none was attached, so the /api/scanner/live surface is always present.
	webServer.StartLiveAuditSweep(ctx)
	go func() {
		logger.Info("Starting web UI", zap.String("bind", *webBind))
		if err := webServer.ListenAndServe(ctx, *webBind); err != nil && err != context.Canceled {
			logger.Error("Web server failed", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("Shutting down...")
	cancel()
	// The out-of-band channel does not stop with ctx, and that is deliberate upstream: lazyOOB binds
	// interactsh-client to context.Background() so a channel outlives the check that opened it. The
	// consequence is that cancelling ctx does not reap it, so shutdown has to — otherwise every burpsy
	// run that opened a channel leaves an interactsh-client behind, holding a registration and a temp
	// file. Closed here rather than through CloseCapabilities because this is the provider this process
	// built, and it is the one thing on this path with a subprocess to collect.
	if oobProvider != nil {
		if err := oobProvider.Close(); err != nil {
			logger.Error("Failed to close the out-of-band channel", zap.Error(err))
		}
	}
	// Seal the capture's tail. Sync rather than Close: handlers may still be
	// unwinding, and Close would unmap segments they are reading spans out of.
	if err := store.Sync(); err != nil {
		logger.Error("Failed to seal capture", zap.Error(err))
	}
}

// resolveScanConfig turns -scan-config into the AuditConfig every audit this process runs defaults to.
//
// Three answers, kept apart: an empty flag is the shipped default; "list" prints the available names and
// exits 0, because a name containing spaces and hyphens is not guessable and an operator should not have
// to read the source to find one; anything else must resolve, and a name that does not is fatal rather
// than a warning that starts the process under a configuration the operator did not ask for.
// domEngineOptions turns the -dom flag into domexec options, or nil for "no DOM engine".
//
// The form is inferred from the value rather than declared by a second mode flag, because a mode
// and a value are two things that can disagree — and one of the disagreements domexec explicitly
// refuses is RemoteURL together with ChromePath. Inferring makes that pair unrepresentable:
//
//   - ""            no engine; DOM checks report a missing capability, as they did before this flag
//   - "chrome"      launch and discover, the zero-value Options the test harness uses
//   - "ws://…"      attach to a CDP server someone else started; its process, its lifetime
//   - anything else a browser binary, resolved here with the same LookPath the launcher will use
func domEngineOptions(flagValue string) (*domexec.Options, error) {
	v := strings.TrimSpace(flagValue)
	switch {
	case v == "":
		return nil, nil
	case v == "chrome":
		return &domexec.Options{}, nil
	case strings.HasPrefix(v, "ws://"), strings.HasPrefix(v, "wss://"):
		return &domexec.Options{RemoteURL: v}, nil
	default:
		// Resolved now so the refusal names the flag. The launcher would resolve the same value
		// later and fail per check, where "no browser" and "nothing to find" read alike.
		if _, err := exec.LookPath(v); err != nil {
			return nil, fmt.Errorf("-dom %q names neither a ws:// CDP endpoint nor a runnable browser: %w", v, err)
		}
		return &domexec.Options{ChromePath: v}, nil
	}
}

func resolveScanConfig(name string) (scanner.AuditConfig, error) {
	base := scanner.DefaultAuditConfig()
	switch name {
	case "":
		return base, nil
	case "list":
		fmt.Println("built-in scan configurations (-scan-config NAME):")
		for _, c := range scanner.BuiltInConfigs {
			fmt.Printf("  %s\n", c.Name)
			for _, k := range c.Keys() {
				if k.Set {
					fmt.Printf("      %-42s = %-5d  %s\n", k.Name, k.Value, k.What)
				} else {
					fmt.Printf("      %-42s   unset  (inherits the default)\n", k.Name)
				}
			}
		}
		fmt.Printf("\n%d of the %d configurations Burp ships set a key this engine implements; the rest\n"+
			"configure crawling, insertion points, parameter relocation and JavaScript analysis, which\n"+
			"this engine does not have, and are omitted rather than offered as knobs that do nothing.\n",
			len(scanner.BuiltInConfigs), scanner.BurpShippedConfigCount)
		os.Exit(0)
	}
	preset, ok := scanner.BuiltInConfigByName(name)
	if !ok {
		return base, fmt.Errorf("no built-in scan configuration is named %q; run -scan-config list to see the %d available",
			name, len(scanner.BuiltInConfigs))
	}
	return preset.Apply(base), nil
}

// startBlindXSS binds the blind-XSS callback listener, or explains why it could not.
//
// Three outcomes, and all three are reported rather than two of them collapsing: no address is
// (nil, nil) — the channel was never asked for; a bind failure is (nil, err) — it was asked for and
// could not be had; success is (listener, nil). The web server turns each into a different sentence at
// /api/blindxss, which is the whole point: an endpoint that answered with an empty callback list in
// any of the first two cases would be claiming it listened and heard nothing.
//
// The failure is logged and returned rather than fatal. internal/blindxss states the contract as "a
// caller MUST surface a bind failure and MUST NOT report a clean result" — surfacing it is what this
// does, and taking the whole process down over an auxiliary listener would be a worse answer than a
// proxy that runs with one capability visibly unavailable.
func startBlindXSS(ctx context.Context, bind, baseURL string, logger *zap.Logger) (*blindxss.Listener, error) {
	bind = strings.TrimSpace(bind)
	if bind == "" {
		if strings.TrimSpace(baseURL) != "" {
			// A base URL with nothing bound is a configuration mistake worth naming: the operator
			// described where payloads should call home to and never opened the socket.
			logger.Warn("-blindxss-url was given without -blindxss, so no callback listener was bound",
				zap.String("url", baseURL))
		}
		return nil, nil
	}
	listener, err := blindxss.NewListener(ctx, blindxss.Options{Addr: bind, BaseURL: baseURL})
	if err != nil {
		logger.Warn("blind-XSS callback listener could not bind, so /api/blindxss will report the "+
			"channel as unavailable rather than as quiet", zap.String("addr", bind), zap.Error(err))
		return nil, err
	}
	logger.Info("blind-XSS callback listener bound",
		zap.String("addr", listener.Addr().String()), zap.String("base_url", listener.BaseURL()))
	if strings.TrimSpace(baseURL) == "" {
		// Worth a line, because it is the difference between a channel that works on an engagement and
		// one that only works from this host. internal/blindxss documents the same caveat.
		logger.Warn("no -blindxss-url was given, so planted payloads will name this host's own bound "+
			"address; set it whenever the rendering browser reaches this listener by another address",
			zap.String("base_url", listener.BaseURL()))
	}
	return listener, nil
}

// pluginSpecs turns the -plugins allowlist into the host's launch specs.
//
// Path only: no args and no env from the flag. Splitting a flag value into an argv is a small shell,
// and this is the one place a shell must not appear — the executable is run directly so that an
// argument containing shell metacharacters is data. A plugin that needs an interpreter should be an
// executable script with a shebang, which is what every language runtime already supports.
func pluginSpecs(allowlist map[string]string) map[string]extension.PluginSpec {
	if len(allowlist) == 0 {
		return nil
	}
	specs := make(map[string]extension.PluginSpec, len(allowlist))
	for name, path := range allowlist {
		specs[name] = extension.PluginSpec{Path: path}
	}
	return specs
}

// readCACert reads the CA certificate the proxy signs with, for the web server to serve at /ca.crt.
//
// Returns nil when interception is off — there is no CA a browser needs then, and the UI's CA link
// keys off the route reporting absence. A read failure is logged rather than fatal: the proxy can
// still intercept for a client that already trusts the CA, so refusing to start would be a worse
// outcome than a missing download link with a reason next to it.
func readCACert(interceptTLS bool, caDir string, logger *zap.Logger) []byte {
	if !interceptTLS {
		return nil
	}
	path := filepath.Join(caDir, "ca.crt")
	pem, err := os.ReadFile(path)
	if err != nil {
		logger.Warn("CA certificate could not be read, so /ca.crt will report it as unavailable",
			zap.String("path", path), zap.Error(err))
		return nil
	}
	return pem
}
