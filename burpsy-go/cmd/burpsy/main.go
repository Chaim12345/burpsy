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
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/blindxss"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/extension"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/oob"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"github.com/burpsy-go/burpsy/internal/upstream"
	"github.com/burpsy-go/burpsy/internal/web"
	"go.uber.org/zap"
	"time"
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
	scanConfig := flag.String("scan-config", "", `run audits under a built-in scan configuration by name ("list" prints them, "list-unapplied" prints the keys this engine cannot apply)`)
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

	// Upstream proxy / SOCKS chaining (Unit 9). Both flags name proxies as URLs, because the scheme is
	// what decides the protocol and a bare host:port would have to be guessed at — see upstream.Parse,
	// which refuses one rather than assuming http://.
	upstreamProxy := flag.String("upstream-proxy", "",
		"route egress through an upstream proxy: http://, https://, socks5:// or socks4:// host:port (userinfo for credentials)")
	upstreamProxyRules := flag.String("upstream-proxy-rule", "",
		"per-destination upstream proxy rules, comma-separated pattern=URL (e.g. '*.internal=socks5://127.0.0.1:1080,api.example.com=direct'); first match wins, ahead of -upstream-proxy")

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

	// Parsed here, before either mode runs, for the same reason as the scan configuration above: a
	// mistyped proxy URL must stop the process at the command line, not become a rule that fails at
	// dial time mid-engagement. Refuse-by-default is the whole point — an unusable proxy that silently
	// became a direct connection is the one outcome an operator who configured a proxy did not ask for.
	upstreamFlags, err := parseUpstreamFlags(*upstreamProxy, *upstreamProxyRules)
	if err != nil {
		log.Fatal(err)
	}

	// CLI mode: when the first positional argument names a subcommand, drive the
	// engines directly (no HTTP) and exit. Global flags above still parse, so
	// `burpsy -db data.db history` reads the same database the proxy writes.
	if flag.NArg() > 0 {
		// The CLI's senders get the flag-configured policy too. It is a third egress surface — `burpsy
		// repeater`, `intruder run`, `audit` all dial through internal/sender — and a -upstream-proxy
		// that covered the server's senders but not these would be the same half-covered settings
		// defect Unit 9 exists to close. Flags only: the console's live edits live in the database the
		// server writes, and a one-shot CLI invocation has no session to apply them to.
		cliUpstream := upstream.NewPolicy()
		applyUpstreamFlags(cliUpstream, upstreamFlags)
		os.Exit(runCLI(flag.Arg(0), flag.Args()[1:], *captureDir, *segmentBytes, *scopeInclude, *scopeExclude, *dbFile, *bchecksDir, *toolsFlag, *domEngine, cliUpstream))
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

	// The CA is loaded once, into one engine, and that engine is shared by the proxy and the web
	// server. Both properties are load-bearing.
	//
	// It used to be loaded twice: once here, and again inside the -passthrough-defaults branch below,
	// which replaced tlsPolicy wholesale and had to re-attach an engine. That produced two distinct
	// TlsEngine values from the same files, and the second load swallowed its error where the first
	// treats one as fatal — so with -passthrough-defaults set, an unreadable CA meant interception
	// silently disabled instead of a refusal to boot.
	//
	// It also has to be a single instance now that the CA can be imported at runtime: an import
	// replaces the CA and empties the leaf cache on the engine it is called on, so a second engine
	// would keep signing with the old CA and serving cached leaves nobody trusts any more.
	var tlsEngine *proxy.TlsEngine
	if *interceptTLS {
		var err error
		tlsEngine, err = proxy.LoadOrGenerateCA(*caDir)
		if err != nil {
			log.Fatalf("Failed to load/generate CA: %v", err)
		}
	}

	tlsPolicy := proxy.NewTlsPolicy()
	if *passthroughDefaults {
		tlsPolicy = proxy.NewTlsPolicy().WithCommonDefaults()
	}
	if tlsEngine != nil {
		tlsPolicy.WithEngine(tlsEngine)
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
		// Closed by webServer.CloseProject (deferred below, once the server exists), not here: an
		// in-console project switch (burpsy-react-ui-dlw2) closes this store and opens another, so a
		// deferred Close of this pointer would close the wrong file twice and the live one never.
		// Tool log and coordinator are owned by the web server below, so restore
		// them after it exists; history/scope/findings restore here.
		if err := persistStore.Restore(store, findingStore, scope, nil, nil, nil, nil); err != nil {
			log.Fatalf("Failed to restore from database: %v", err)
		}
		// Message, exchange and finding sinks — including the triage delete sink, without which a
		// finding deleted in the UI is restored on the next start. Installed through the web
		// package so every durable write takes the project-switch lock from the first capture on.
		web.InstallCaptureSinks(store, findingStore, persistStore)
	}

	// The upstream proxy policy every egress path in this process shares: the proxy listener's
	// origin-facing leg and every sender built below hold this same object, so a rule edited in the
	// console reaches both without a restart.
	//
	// Order is load-bearing. Persisted rules are restored first, then the flag-named ones are applied
	// over them — and Policy.Set upserts by pattern, so a rule named on the command line that is
	// already in the database replaces it in place rather than becoming a second, unreachable copy.
	// Doing this the other way round would have Restore wipe the flags entirely.
	upstreamPolicy := upstream.NewPolicy()
	// The global SOCKS layer, one instance shared by every egress surface — the sender, the proxy
	// listener and the console. One instance rather than a copy per surface because the setting is
	// global: a carrier the sender honours and the proxy does not is a panel that looks right and a
	// browser that goes out the wrong way (burpsy-react-ui-mr83 part 3).
	upstreamCarrier := upstream.NewCarrier()
	if persistStore != nil {
		// Fatal, not a warning. Starting under a proxy policy we could not read means starting with
		// traffic going somewhere the operator did not choose — including straight to the target — and
		// that is not a decision to make behind their back.
		if err := persistStore.LoadUpstreamProxy(upstreamPolicy); err != nil {
			log.Fatalf("Failed to restore the upstream proxy policy: %v", err)
		}
		// The carrier is restored in the same block and for the same reason, and FATAL on a refusal
		// for the same reason: starting with a layer the operator configured but this process could
		// not read means traffic going out a way they did not choose, and the failure mode is
		// indistinguishable from "the SOCKS proxy is down".
		if _, cerr := persistStore.LoadUpstreamCarrier(upstreamCarrier); cerr != nil {
			log.Fatalf("Could not read the saved SOCKS carrier: %v", cerr)
		}
	}
	applyUpstreamFlags(upstreamPolicy, upstreamFlags)
	if persistStore != nil && len(upstreamFlags) > 0 {
		// Mirror the flag-named rules back, so they are in the database the console reads and edits
		// rather than existing only in this process's memory. Without this the panel would show a rule
		// it could remove but that would silently return on the next start.
		persistStore.SaveUpstreamProxy(upstreamPolicy)
	}
	if !upstreamPolicy.Empty() {
		logger.Info("upstream proxy policy active",
			zap.String("default", upstreamPolicy.Default().Display()),
			zap.Int("rules", len(upstreamPolicy.Rules())))
	}
	// Settings → Network: per-host HTTP credentials and per-host TLS client identities.
	//
	// Built here, before either server, because three places that cannot see each other
	// read the same two stores: the web API edits them, every internal/sender egress
	// presents them, and the proxy's upstream leg presents the certificate on an
	// intercepted connection. One set of pointers threaded through all three is the only
	// arrangement in which the panel and the wire agree; separate copies would give the
	// operator a panel editing one and a request carrying another.
	//
	// Restored here rather than through persistStore.Restore for two reasons. The stores
	// have to exist before the proxy config below, which Restore's call site does not; and
	// rebuilding a client certificate means re-reading a PKCS#12 file that may have been
	// deleted since, which produces per-row failures that must be reported rather than
	// folded into one error. Restore has no shape for that, and widening its seven
	// positional parameters to nine to add one that cannot use them would be worse than
	// two explicit calls.
	platformAuth, clientCerts, netAuthNotes := restoreNetworkAuth(persistStore, logger)

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
	// Same scope object the relay and the web API use, so "Only intercept in-scope messages" filters
	// against the rules the operator can actually see on the Scope page. The web server attaches this
	// too; doing it here as well means the standalone-proxy path (no web server) is not left with an
	// engine whose toggle silently does nothing.
	interceptEngine.SetScope(scope)
	matchReplaceRules := matchreplace.NewRuleSet()
	// The proxy's live option set — Burp's response-modification switches. One set handed to both
	// the relay and the web API, the same single-pointer rule as the TLS policy and the Match &
	// Replace rules: a panel that described a different set than the relay applies is the drift
	// this project keeps closing. proxyOptions aliases the config's own set (picked up below,
	// after the builder chain) rather than a second NewOptions, because NewProxyConfig seeds
	// engine defaults into its set — the WebSocket handshake strip starts on — and a fresh
	// all-off set attached over it would silently have turned that default off.
	// The unified traffic log (burpsy-react-ui-6dt): one instance for the listener and for the
	// console, so a proxied request and a Repeater send land in the same ordered log, are
	// gated by the same capture axis, and are persisted by the same sink. Built here rather
	// than inside the web server because the listener's relay goroutines read it from the
	// moment the proxy starts, and the web server is constructed after that.
	toolLog := toollog.New()

	// One streaming policy, shared by the proxy's response path and the console that edits it. Built
	// here because the restore below and the builder chain both need it: the persisted document has
	// to reach the proxy leg on the same pass that reaches the sender, or an event stream would be
	// honoured in Repeater and buffered through the proxy — the split burpsy-react-ui-wet3 records.
	streamingPolicy := proxy.NewStreamingPolicy()
	// The upstream-TLS policy, declared beside the streaming one and BEFORE the restore that replaces
	// it, because the builder chain further down reads this variable. Attaching it in the chain would
	// capture the pre-restore value and leave the proxy verifying against the default while the
	// operator believed their restored setting applied -- the panel and the leg disagreeing, which is
	// the state burpsy-react-ui-f365 found with the setting absent entirely.
	restoredTLSPolicy := proxy.NewTLSPolicy()

	// The listener's live resolution/100-continue holder. Declared here, before the builder chain,
	// for the same reason restoredTLSPolicy is: the chain would otherwise capture a value built
	// later, and the restore below would write into a holder the server never reads
	// (burpsy-react-ui-o1eu).
	proxyNetwork := proxy.NewNetworkSettings()

	proxyConfig := proxy.NewProxyConfig(store).
		WithNetworkSettings(proxyNetwork).
		// The SAME credential store the sender holds, restored above. One store for both legs: two
		// would let the Settings panel describe rules that Repeater honours and the proxy does not,
		// and the symptom would be an authenticated tool beside an unauthenticated browser
		// (burpsy-react-ui-trcy). The NTLMv2 codec landed in 3fb2ce1 and was unreachable for the
		// traffic that needed it until this line existed.
		WithPlatformAuth(platformAuth).
		WithStreaming(streamingPolicy).
		WithScope(scope).
		WithTlsPolicy(tlsPolicy).
		WithMatchReplace(matchReplaceRules).
		WithLogger(logger).
		WithScanner(passiveScanner).
		WithFindings(findingStore).
		WithIntercept(interceptEngine).
		// The shared cookie jar, fed by traffic through this listener — Burp's "by default, the
		// cookie jar is updated based on traffic from the Proxy". The same coordinator the web
		// server and the scanner hold, so a session an operator establishes in their browser is the
		// session the other tools send with. Before this the jar was fed only by login macros and
		// the crawler's session gate, while the Session page told the operator that browsing through
		// the proxy would fill it.
		WithCookieJar(sessionCoord).
		// The listener's own upstream leg. This is the half of Unit 9 that is easy to forget: without
		// it an operator sets a corporate proxy, watches the scanner's traffic take it, and never
		// learns that everything their browser drove through the listener went out direct.
		WithUpstreamProxy(upstreamPolicy).
		WithUpstreamCarrier(upstreamCarrier).
		// The upstream leg of an intercepted TLS connection. Without this, an app requiring
		// a client certificate could only be reached by putting its host on the TLS
		// passthrough list — which is to say by giving up interception, which is the one
		// thing the operator started this tool to do.
		WithClientCerts(clientCerts).
		// What the listener relayed for the operator's browser is logged beside what burpsy's
		// own tools sent — Logger's coverage, not just the tools' (burpsy-react-ui-6dt).
		WithToolLog(toolLog)
	proxyOptions := proxyConfig.Options()

	// Start proxy server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Attached HERE rather than in the builder chain above, because the restore that replaces this
	// policy runs between the two. A builder-chain attachment captures the pre-restore value and leaves
	// the proxy verifying against the default while the operator believes their restored setting
	// applied -- the panel and the leg disagreeing, which is the state burpsy-react-ui-f365 found with
	// the setting absent entirely.
	proxyConfig.WithUpstreamTLS(restoredTLSPolicy)

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
	// The carrier goes ON THE CONFIG, not just on the sender afterwards. The transport's client is
	// built during construction and captures the carrier then, so a WithUpstreamCarrier that only
	// set the field would leave the client holding a nil layer — and the live pass found exactly
	// that: the console reported the carrier configured, every dial site read the field, and the
	// connection still went out direct.
	senderConfig := egressSenderConfig(upstreamPolicy, platformAuth, clientCerts)
	senderConfig.UpstreamCarrier = upstreamCarrier
	httpSender := sender.NewSender(senderConfig).WithUpstreamCarrier(upstreamCarrier)

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
				// The proxy leg reads the same streaming settings, and the sender's copy is the
				// confirmed one — Normalise has already run, so this is what the operator's document
				// actually became. Pushed here rather than at the API so a restart honours the setting
				// for browser traffic too; without it, an event stream would be honoured in Repeater
				// and buffered through the proxy, which is the split burpsy-react-ui-wet3 records.
				applied := httpSender.Network()
				if err := streamingPolicy.Set(applied.Streaming.Hosts, time.Duration(applied.Streaming.TimeoutMS)*time.Millisecond); err != nil {
					logger.Warn("Proxy streaming policy refused the restored window", zap.Error(err))
				}
				// The three response-handling switches, restored on the same pass: a restart must honour
				// "store", "strip chunked metadata" and "treat text/event-stream as streaming" for browser
				// traffic too, or they would apply in Repeater and silently not through the proxy.
				streamingPolicy.SetResponseHandling(
					applied.Streaming.StoreStreamed(),
					applied.Streaming.StripChunkedMetadata,
					applied.Streaming.UseTextEventStreamHeader,
				)
				// The resolution overrides and 100-continue handling, restored onto the listener for
				// the same reason: a restart must honour what the operator saved, or their
				// split-horizon override works in Repeater and not in the browser they browse
				// through the proxy with (burpsy-react-ui-o1eu).
				proxyNetwork.Set(applied.Resolution, applied.Continue)
				// The TLS policy is restored on the same pass and for the same reason: a verification
				// setting that only reached the sender would leave every intercepted connection
				// verifying while the operator believed they had turned it off for a self-signed lab
				// target — the panel's promise and the proxy's behaviour disagreeing, which is the state
				// burpsy-react-ui-f365 found with the setting absent entirely.
				// Mutating the policy the proxy already holds rather than replacing the variable. The
				// builder chain attached this instance before the restore ran, so assigning a new one
				// here would leave the proxy on the pre-restore default while the console reported the
				// restored value -- the panel and the leg disagreeing, which is the state
				// burpsy-react-ui-f365 found with the setting absent entirely.
				restoredTLSPolicy.WithVerify(applied.TLS.Verify)
				if minErr := restoredTLSPolicy.WithMinVersion(applied.TLS.MinVersion); minErr != nil {
					logger.Warn("Proxy TLS policy refused the restored minimum version", zap.Error(minErr))
				}
				if caPath := applied.TLS.RootCAPath; caPath != "" {
					if caErr := restoredTLSPolicy.WithRootCAFile(caPath); caErr != nil {
						logger.Warn("Proxy TLS policy could not load the restored custom CA", zap.String("path", caPath), zap.Error(caErr))
					}
				}
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
	// Capture-time scanning reads the same run configuration the audit does (saq3.3.3). Every capture
	// handle is built around passiveScanner, so this one line reaches proxy, crawl, Repeater and
	// API-scan capture.
	passiveScanner.WithRunConfigSource(activeScanner)

	// Persisted scan-config overrides still apply last, after the flag chain — but through
	// webServer.WithPersist below (restoreProjectScanState), not here: the overrides are project-level
	// and must be reloaded when the console switches project, and the restore there first captures
	// these flag-built defaults as the baseline a project with no overrides gets (burpsy-react-ui-z4ml).

	// The blind-XSS callback channel, bound before the web server so the API can report either the live
	// listener or the reason there is none. A bind failure is deliberately not fatal: everything else
	// this process does still works, and the honest outcome is a surface that says "no channel, because
	// X" rather than a refusal to start.
	blindXSSListener, blindXSSErr := startBlindXSS(ctx, *blindXSSBind, *blindXSSURL, logger)
	if blindXSSListener != nil {
		defer blindXSSListener.Close()
	}

	// Start web server
	//
	// upstreamSenderConfig rather than DefaultSenderConfig at both sender sites below: these two are
	// every request the console originates (repeater, intruder, session macros, sequencer captures) and
	// every active-audit probe, and a settings panel that covered the proxy listener but not these
	// would be the same half-covered defect from the other side.
	webServer := web.NewServer(store, scope).
		// First in the chain, so everything downstream — including WithPersist's restore and
		// its save sink — is wired to the log the proxy is already recording into.
		WithToolLog(toolLog).
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
		// The relay itself, so the console can read where its listener is bound and move it
		// at runtime (burpsy-react-ui-77m): a bind change that used to need a process restart
		// is now a PUT, and the panel reports the address the accept loop actually serves.
		WithProxyServer(proxyServer).
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
		// The same engine the proxy signs with, so an imported CA takes effect on live traffic and
		// /ca.crt serves whichever CA is in force. nil when -intercept-tls is off, which is what
		// makes the import endpoint refuse rather than store a setting nothing reads.
		WithTLSEngine(tlsEngine, *caDir).
		WithBindAddrs(*proxyBind, *webBind).
		WithDOMEngine(*domEngine).
		// The same object the proxy and the senders hold, so /api/network/proxy edits what is actually
		// consulted rather than a copy — and so its `attached` field can report both surfaces truthfully.
		WithUpstreamProxy(upstreamPolicy).
		// The same carrier the proxy and the senders hold, so /api/network/proxy's carrier edit
		// reaches the dial path rather than a copy — and so its `attached` field can report every
		// surface truthfully. Without it the panel would accept a carrier edit, report the layer as
		// configured, and nothing would be carried (burpsy-react-ui-mr83 part 3).
		WithUpstreamCarrier(upstreamCarrier).
		// The same pointers the proxy and every sender above hold, so the panel edits what
		// the wire presents. The notes carry the bindings that could not be rebuilt, so a
		// PKCS#12 file deleted between sessions shows up on the panel rather than only in a
		// log the operator is not reading.
		WithNetAuth(platformAuth, clientCerts).
		WithNetAuthRestoreNotes(netAuthNotes)
	if persistStore != nil {
		// Restore the web-owned stores (match & replace, session, organizer,
		// tool log) and mirror their tool activity.
		webServer.WithPersist(persistStore)
		// Close whichever project file is open at exit — after an in-console switch that is no
		// longer persistStore (burpsy-react-ui-dlw2).
		defer webServer.CloseProject()
		// The live sweep's cross-run seen ledger (apfh) survives restarts: WithPersist above loads it
		// (restoreProjectScanState) before StartLiveAuditSweep runs its first tick, and reloads it on
		// an in-console project switch so one engagement's audit history does not suppress another's.
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
		// The two coupling switches survive restarts too (burpsy-react-ui-n1fi).
		applyOOS, autoAdd := persistStore.LoadTlsPassthroughMode()
		tlsPolicy.SetApplyOutOfScope(applyOOS)
		tlsPolicy.SetAutoAddOnFailure(autoAdd)
		// Runtime edits to the proxy's response-modification switches survive restarts.
		// Without this, every switch the operator turned on in Proxy → Options came back
		// off after a restart while the panel still rendered a working panel — the
		// silent-revert failure this project treats as a defect rather than a limitation.
		//
		// A key in the saved document that this build does not recognise is logged by
		// name and skipped. That is the honest handling of a retired or renamed option:
		// applying it is impossible, and dropping it without a word would leave the
		// operator with a switch that disappeared and no way to find out why.
		if saved, err := persistStore.LoadProxyOptions(); err != nil {
			logger.Warn("could not restore proxy response-modification switches", zap.Error(err))
		} else {
			var unknown []string
			applied := 0
			for key, on := range saved {
				if err := proxyOptions.Set(proxy.OptionKey(key), on); err != nil {
					unknown = append(unknown, key)
					continue
				}
				applied++
			}
			if len(unknown) > 0 {
				sort.Strings(unknown)
				logger.Warn("ignored unrecognised proxy options while restoring",
					zap.Strings("keys", unknown),
					zap.Int("applied", applied))
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

// resolveScanConfig turns -scan-config into the AuditConfig every audit this process runs defaults to.
//
// Five answers, kept apart: an empty flag is the shipped default; "list" prints the available names and
// exits 0, because a name containing spaces and hyphens is not guessable and an operator should not have
// to read the source to find one; "list-unapplied" prints every key this engine accepts but does not
// apply, with the reason, which is the other half of what a scan configuration can say; a path ending in
// .json (or containing a path separator) is one of Burp's own configuration files, parsed with
// ParseBurpConfig so the engine honours its insertion-point, relocation and check-class keys and reports
// what it cannot apply; anything else must resolve as a built-in name, and a name that does not is fatal
// rather than a warning that starts the process under a configuration the operator did not ask for.
func resolveScanConfig(name string) (scanner.AuditConfig, error) {
	base := scanner.DefaultAuditConfig()
	switch name {
	case "":
		return base, nil
	case "list":
		fmt.Println("built-in scan configurations (-scan-config NAME, or -scan-config /path/to/burp-config.json):")
		for _, c := range scanner.BuiltInConfigs {
			fmt.Printf("  %s\n", c.Name)
			unsetHonoured := 0
			for _, k := range c.Keys() {
				switch {
				case k.Set && k.Applies:
					fmt.Printf("      %-42s = %-5d  %s\n", k.Name, k.Value, k.What)
				case k.Set && !k.Applies:
					// A key this engine cannot apply is reported, never printed as if it had a
					// value that means something here.
					fmt.Printf("      %-42s  set, but not applied here: %s\n", k.Name, k.What)
				case !k.Set && k.Applies:
					unsetHonoured++
				}
			}
			fmt.Printf("      (%d further key(s) this engine honours are left unset by this configuration)\n", unsetHonoured)
		}
		fmt.Printf("\n%d of the %d configurations Burp ships are transcribed above; %d of them set at\n"+
			"least one key this engine honours, so loading one of those files takes effect. The others\n"+
			"set only crawl tuning or DOM analysis this engine has no equivalent of:\n"+
			"every such key is attributed rather than dropped, listed by `-scan-config list-unapplied`.\n"+
			"A Burp configuration file can be loaded directly by passing its path instead of a name.\n",
			len(scanner.BuiltInConfigs), scanner.BurpShippedConfigCount,
			scanner.BurpShippedConfigsSettingAnHonouredKey)
		os.Exit(0)
	case "list-unapplied":
		// The other half of the accounting, in the form an operator comparing against Burp's own
		// settings UI can use: every key the engine cannot apply, with the reason, rather than a
		// count nobody can act on.
		fmt.Println("keys under scanner/* that this engine accepts but does not apply:")
		for _, k := range scanner.BuiltInConfigKeys() {
			if !k.Applies {
				fmt.Printf("  %-72s  %s\n", k.BurpKey, k.What)
			}
		}
		os.Exit(0)
	}
	if strings.HasSuffix(name, ".json") || strings.ContainsRune(name, '/') || strings.ContainsRune(name, os.PathSeparator) {
		data, err := os.ReadFile(name)
		if err != nil {
			return base, fmt.Errorf("-scan-config: reading configuration file: %w", err)
		}
		applied, unapplied, perr := scanner.ApplyBurpConfigFile(base, data)
		if perr != nil {
			return base, fmt.Errorf("-scan-config: %w", perr)
		}
		if len(unapplied) > 0 {
			fmt.Printf("scan configuration %s: keys this engine cannot apply: %s\n", name, strings.Join(unapplied, ", "))
		}
		return applied, nil
	}
	preset, ok := scanner.BuiltInConfigByName(name)
	if !ok {
		return base, fmt.Errorf("no built-in scan configuration is named %q; run -scan-config list to see the %d available",
			name, len(scanner.BuiltInConfigs))
	}
	applied, unapplied := preset.ApplyWithReport(base)
	if len(unapplied) > 0 {
		fmt.Printf("scan configuration %q: keys this engine cannot apply: %s\n", name, strings.Join(unapplied, ", "))
	}
	return applied, nil
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

// upstreamFlagRule is one validated entry from -upstream-proxy / -upstream-proxy-rule.
//
// An empty pattern is the default arm (-upstream-proxy), which is why the two flags parse into one
// slice: applying them is then a single ordered pass and there is no second code path for the default
// to drift down.
type upstreamFlagRule struct {
	pattern string
	proxy   string
}

// parseUpstreamFlags validates both upstream-proxy flags and returns what to apply, in order.
//
// Every proxy URL is run through upstream.Parse here rather than at apply time, so the whole flag set
// is judged before any of it takes effect: a command line with a good default and one typo'd rule is
// refused entirely rather than starting under half of what the operator asked for.
//
// The rule syntax is `pattern=URL`, split on the *first* '=' — a proxy URL can contain '=' in a
// password, and splitting on the last one would silently mangle exactly the credentials that must not
// be guessed at.
func parseUpstreamFlags(def, rules string) ([]upstreamFlagRule, error) {
	var out []upstreamFlagRule
	if strings.TrimSpace(def) != "" {
		if _, err := upstream.Parse(def); err != nil {
			return nil, fmt.Errorf("-upstream-proxy: %w", err)
		}
		out = append(out, upstreamFlagRule{proxy: def})
	}
	for _, entry := range strings.Split(rules, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		pattern, proxyURL, found := strings.Cut(entry, "=")
		if !found {
			return nil, fmt.Errorf("-upstream-proxy-rule %q is not pattern=URL; write for example '*.internal=socks5://127.0.0.1:1080'",
				entry)
		}
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return nil, fmt.Errorf("-upstream-proxy-rule %q names no host pattern; use * for every destination", entry)
		}
		// "direct" and the empty value are legal and mean "exempt this pattern from the default", which
		// is the only way to keep one host off a broad proxy rule. upstream.Parse accepts both.
		if _, err := upstream.Parse(proxyURL); err != nil {
			return nil, fmt.Errorf("-upstream-proxy-rule for %q: %w", pattern, err)
		}
		out = append(out, upstreamFlagRule{pattern: pattern, proxy: proxyURL})
	}
	return out, nil
}

// applyUpstreamFlags installs already-validated flag rules onto a policy.
//
// No error return, and that is the point of splitting it from parseUpstreamFlags: everything here was
// parsed at the command line, so the only way Set or SetDefault could fail is a bug in this pairing
// rather than anything an operator typed. Set upserts by pattern, which is what makes re-applying flags
// over restored database rules a dedup rather than a duplication.
func applyUpstreamFlags(policy *upstream.Policy, rules []upstreamFlagRule) {
	for _, rule := range rules {
		if rule.pattern == "" {
			if err := policy.SetDefault(rule.proxy); err != nil {
				// Unreachable: parseUpstreamFlags already accepted this exact string.
				log.Fatalf("upstream proxy default %q passed validation then failed to apply: %v",
					rule.proxy, err)
			}
			continue
		}
		if _, err := policy.Set(rule.pattern, rule.proxy); err != nil {
			log.Fatalf("upstream proxy rule for %q passed validation then failed to apply: %v",
				rule.pattern, err)
		}
	}
}

// upstreamSenderConfig is DefaultSenderConfig with the process's upstream proxy policy attached.
//
// A helper rather than a literal at each site because there are two of them here and one more in the
// CLI, and the field being set is exactly the thing that was dead before Unit 9 — SenderConfig.ProxyURL
// was read by nothing configurable, and every construction site used DefaultSenderConfig(). Upstream
// rather than ProxyURL: the policy is shared by reference, so a console edit reaches senders already
// built, which a URL string copied into a config could never do.
func egressSenderConfig(policy *upstream.Policy, auth *netauth.Credentials, certs alpn.ClientCertSource) *sender.SenderConfig {
	config := sender.DefaultSenderConfig()
	config.Upstream = policy
	config.PlatformAuth = auth
	config.ClientCerts = certs
	return config
}

// restoreNetworkAuth rebuilds the Settings → Network stores from the durable mirror,
// returning them plus one note per row it could not rebuild.
//
// # Why a partial restore is the right answer, and why it must be reported
//
// Nothing here is fatal. A platform-authentication row written by a build that had a
// scheme this one does not is dropped rather than coerced — coercing it to Basic would
// send the operator's password to a host under a scheme they never chose — and a
// client-certificate binding whose PKCS#12 file was deleted between sessions cannot be
// rebuilt at all. Refusing to start over either would take the whole engagement down for
// one stale row.
//
// But dropping them silently is the failure this codebase treats as a bug: the binding
// was on the operator's panel yesterday, and a panel that lists it while no handshake
// carries it is a partial result looking complete. So each failure comes back as a line
// the panel shows, *and* goes to the log. Two sinks because the two readers are different
// people at different times: the log is for afterwards, the panel is for the person who
// can still fix it.
//
// A nil store — no -db — restores nothing and reports nothing, which is not a failure but
// an empty first run.
func restoreNetworkAuth(store *persist.Store, logger *zap.Logger) (*netauth.Credentials, *netauth.ClientCerts, []string) {
	credentials := netauth.NewCredentials()
	certs := netauth.NewClientCerts()
	if store == nil {
		return credentials, certs, nil
	}

	var notes []string
	record := func(err error) {
		notes = append(notes, err.Error())
		logger.Warn("network authentication row could not be restored", zap.Error(err))
	}

	if rows, err := store.LoadPlatformAuth(); err != nil {
		// A failed read of the whole table is one note, not none: the alternative is a panel
		// that shows an empty rule list for a database that has rules in it.
		record(fmt.Errorf("reading stored platform-authentication rules: %w", err))
	} else {
		restored, failures := netauth.RestoreCredentials(rows)
		credentials = restored
		for _, failure := range failures {
			record(failure)
		}
	}

	if rows, err := store.LoadClientCerts(); err != nil {
		record(fmt.Errorf("reading stored client-certificate bindings: %w", err))
	} else {
		restored, failures := netauth.RestoreClientCerts(rows)
		certs = restored
		for _, failure := range failures {
			record(failure)
		}
	}
	return credentials, certs, notes
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
