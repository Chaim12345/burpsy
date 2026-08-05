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

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
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
	interceptTLS := flag.Bool("intercept-tls", true, "enable TLS interception (disable with -intercept-tls=false)")
	caDir := flag.String("ca-dir", proxy.DefaultCADir(), "CA certificate directory")
	segmentBytes := flag.Uint64("segment-bytes", core.DefaultSegmentTargetBytes, "target bytes per segment file")
	bchecksDir := flag.String("bchecks", "", "load PortSwigger BCheck files and passively scan responses")
	// SCAN-03: the shipped configurations were reachable from nothing. This sets the default every
	// audit this process runs uses; a per-audit override goes on the request body. "list" prints the
	// names and exits, because the names contain spaces and hyphens and guessing them is hopeless.
	scanConfig := flag.String("scan-config", "", `run audits under a built-in scan configuration by name ("list" prints them)`)

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

	// CLI mode: when the first positional argument names a subcommand, drive the
	// engines directly (no HTTP) and exit. Global flags above still parse, so
	// `burpsy -db data.db history` reads the same database the proxy writes.
	if flag.NArg() > 0 {
		os.Exit(runCLI(flag.Arg(0), flag.Args()[1:], *captureDir, *segmentBytes, *scopeInclude, *scopeExclude, *dbFile))
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

	// Start web server
	webServer := web.NewServer(store, scope).
		WithLogger(logger).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		// WithScope is not optional here even though ActiveScanner treats it as such: without it this
		// scanner's probes are authorised against nothing, and this is the scanner every /api/audit call
		// uses. The web server only builds a scoped one of its own when none was attached, so leaving it
		// off here meant the flag-configured engagement scope silently did not apply to active probes.
		// WithAuditConfig carries -scan-config, so the endpoint's default is the one the operator named.
		WithScanner(scanner.NewActiveScanner(store, logger).
			WithSender(sender.NewSender(sender.DefaultSenderConfig())).
			WithScope(scope).
			WithAuditConfig(auditConfig)).
		WithPassiveScanner(passiveScanner).
		WithFindings(findingStore).
		WithIntercept(interceptEngine).
		// So /ca.crt can serve it. Read here rather than in the web server because this is where the
		// CA directory is known. An unreadable file is a warning, not fatal: interception still works
		// for a client that already trusts the CA, and the operator gets told why the download is
		// missing instead of the link silently staying hidden.
		WithCACertPEM(readCACert(*interceptTLS, *caDir, logger))
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
