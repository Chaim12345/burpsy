package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/upstream"
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
	toolsFlag := flag.String("tools", "", "allowlist external tools for `run tool` bchecks and for `extscan`: sqlmap=/usr/bin/sqlmap,ffuf=ffuf,nuclei=nuclei (comma-separated name=path)")
	// SCAN-03: the shipped configurations were reachable from nothing. This sets the default every
	// audit this process runs uses; a per-audit override goes on the request body. "list" prints the
	// names and exits, because the names contain spaces and hyphens and guessing them is hopeless.
	scanConfig := flag.String("scan-config", "", `run audits under a built-in scan configuration by name ("list" prints them)`)

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
		os.Exit(runCLI(flag.Arg(0), flag.Args()[1:], *captureDir, *segmentBytes, *scopeInclude, *scopeExclude, *dbFile, *bchecksDir, *toolsFlag, cliUpstream))
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

	// The upstream proxy policy every egress path in this process shares: the proxy listener's
	// origin-facing leg and every sender built below hold this same object, so a rule edited in the
	// console reaches both without a restart.
	//
	// Order is load-bearing. Persisted rules are restored first, then the flag-named ones are applied
	// over them — and Policy.Set upserts by pattern, so a rule named on the command line that is
	// already in the database replaces it in place rather than becoming a second, unreachable copy.
	// Doing this the other way round would have Restore wipe the flags entirely.
	upstreamPolicy := upstream.NewPolicy()
	if persistStore != nil {
		// Fatal, not a warning. Starting under a proxy policy we could not read means starting with
		// traffic going somewhere the operator did not choose — including straight to the target — and
		// that is not a decision to make behind their back.
		if err := persistStore.LoadUpstreamProxy(upstreamPolicy); err != nil {
			log.Fatalf("Failed to restore the upstream proxy policy: %v", err)
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

	// Create proxy config
	interceptEngine := intercept.NewEngine()
	proxyConfig := proxy.NewProxyConfig(store).
		WithScope(scope).
		WithTlsPolicy(tlsPolicy).
		WithLogger(logger).
		WithScanner(passiveScanner).
		WithFindings(findingStore).
		WithIntercept(interceptEngine).
		// The listener's own upstream leg. This is the half of Unit 9 that is easy to forget: without
		// it an operator sets a corporate proxy, watches the scanner's traffic take it, and never
		// learns that everything their browser drove through the listener went out direct.
		WithUpstreamProxy(upstreamPolicy)

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

	// Start web server
	//
	// upstreamSenderConfig rather than DefaultSenderConfig at both sender sites below: these two are
	// every request the console originates (repeater, intruder, session macros, sequencer captures) and
	// every active-audit probe, and a settings panel that covered the proxy listener but not these
	// would be the same half-covered defect from the other side.
	webServer := web.NewServer(store, scope).
		WithLogger(logger).
		WithSender(sender.NewSender(upstreamSenderConfig(upstreamPolicy))).
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
		WithScanner(scanner.NewActiveScanner(store, logger).
			WithSender(sender.NewSender(upstreamSenderConfig(upstreamPolicy))).
			WithScope(scope).
			WithCorpusChecks(passiveScanner.ActiveChecks()).
			WithToolRunner(toolRunner).
			WithAuditConfig(auditConfig)).
		WithPassiveScanner(passiveScanner).
		WithFindings(findingStore).
		WithIntercept(interceptEngine).
		// So /ca.crt can serve it. Read here rather than in the web server because this is where the
		// CA directory is known. An unreadable file is a warning, not fatal: interception still works
		// for a client that already trusts the CA, and the operator gets told why the download is
		// missing instead of the link silently staying hidden.
		WithCACertPEM(readCACert(*interceptTLS, *caDir, logger)).
		// The same object the proxy and the senders hold, so /api/network/proxy edits what is actually
		// consulted rather than a copy — and so its `attached` field can report both surfaces truthfully.
		WithUpstreamProxy(upstreamPolicy)
	if persistStore != nil {
		// Restore the web-owned stores (match & replace, session, organizer,
		// tool log) and mirror their tool activity.
		webServer.WithPersist(persistStore)
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
func upstreamSenderConfig(policy *upstream.Policy) *sender.SenderConfig {
	config := sender.DefaultSenderConfig()
	config.Upstream = policy
	return config
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
