package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/mcp"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/sitemap"
	"github.com/burpsy-go/burpsy/internal/web"
	"go.uber.org/zap"
)

func main() {
	proxyBind := flag.String("proxy", "127.0.0.1:8080", "proxy bind address")
	captureDir := flag.String("capture-dir", "", "directory for segment-based capture")
	scopeInclude := flag.String("scope-include", "", "include host pattern in scope")
	scopeExclude := flag.String("scope-exclude", "", "exclude host pattern in scope")
	interceptTLS := flag.Bool("intercept-tls", false, "enable TLS interception")
	caDir := flag.String("ca-dir", proxy.DefaultCADir(), "CA certificate directory")
	segmentBytes := flag.Uint64("segment-bytes", core.DefaultSegmentTargetBytes, "target bytes per segment file")
	bchecksDir := flag.String("bchecks", "", "load PortSwigger BCheck files and passively scan responses")
	scanConfig := flag.String("scan-config", "", `run audits under a built-in scan configuration by name ("list" prints them)`)

	flag.Parse()

	auditConfig, err := resolveScanConfig(*scanConfig)
	if err != nil {
		log.Fatal(err)
	}

	logger, lerr := zap.NewProduction()
	if lerr != nil {
		log.Fatalf("Failed to initialize logger: %v", lerr)
	}
	defer logger.Sync()

	var store *core.TrafficStore
	if *captureDir != "" {
		store, err = core.NewTrafficStoreWithCaptureDir(*captureDir, *segmentBytes)
	} else {
		store = core.NewTrafficStore()
	}
	if err != nil {
		log.Fatalf("Failed to create traffic store: %v", err)
	}

	sc := core.NewScope()
	if *scopeInclude != "" {
		sc.AddInclude(*scopeInclude)
	}
	if *scopeExclude != "" {
		sc.AddExclude(*scopeExclude)
	}

	tlsPolicy := proxy.NewTlsPolicy()
	if *interceptTLS {
		engine, err := proxy.LoadOrGenerateCA(*caDir)
		if err != nil {
			log.Fatalf("Failed to load/generate CA: %v", err)
		}
		tlsPolicy.WithEngine(engine)
	}

	findingStore := core.NewFindingStore()

	var passiveScanner *scanner.PassiveScanner
	if *bchecksDir != "" {
		ps, err := scanner.LoadDir(*bchecksDir, store, sc, logger)
		if err != nil {
			log.Fatalf("Failed to load BChecks from %s: %v", *bchecksDir, err)
		}
		passiveScanner = ps
	} else {
		passiveScanner = scanner.NewPassiveScanner(store, logger)
	}

	interceptEngine := intercept.NewEngine()
	sm := sitemap.New()
	sm.Follow(store)

	proxyConfig := proxy.NewProxyConfig(store).
		WithScope(sc).
		WithTlsPolicy(tlsPolicy).
		WithLogger(logger).
		WithScanner(passiveScanner).
		WithFindings(findingStore).
		WithIntercept(interceptEngine)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyServer := proxy.NewServer(proxyConfig)
	go func() {
		logger.Info("Starting proxy", zap.String("bind", *proxyBind))
		if err := proxyServer.ListenAndServe(ctx, *proxyBind); err != nil && err != context.Canceled {
			logger.Error("Proxy server failed", zap.Error(err))
		}
	}()

	tasks := dash.NewRegistry()
	events := dash.NewEventLog()
	tasks.WithEvents(events)

	snd := sender.NewSender(sender.DefaultSenderConfig())
	activeScan := scanner.NewActiveScanner(store, logger).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithScope(sc).
		WithAuditConfig(auditConfig)

	web.NewServer(store, sc).
		WithLogger(logger).
		WithSender(snd).
		WithScanner(activeScan).
		WithPassiveScanner(passiveScanner).
		WithFindings(findingStore).
		WithIntercept(interceptEngine).
		WithSitemap(sm).
		WithTasks(tasks).
		WithEvents(events)

	mcpServer := mcp.NewServer(store, sc, findingStore, snd, activeScan, passiveScanner, tasks, events, logger)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		logger.Info("Shutting down...")
		cancel()
		if err := store.Sync(); err != nil {
			logger.Error("Failed to seal capture", zap.Error(err))
		}
		os.Exit(0)
	}()

	if err := mcpServer.ServeStdio(ctx); err != nil {
		logger.Fatal("MCP server failed", zap.Error(err))
	}
}

func resolveScanConfig(name string) (scanner.AuditConfig, error) {
	base := scanner.DefaultAuditConfig()
	switch name {
	case "":
		return base, nil
	case "list":
		printScanConfigs()
		os.Exit(0)
		return base, nil
	}
	preset, ok := scanner.BuiltInConfigByName(name)
	if !ok {
		return base, fmt.Errorf("no built-in scan configuration named %q; run with -scan-config list to see the %d available", name, len(scanner.BuiltInConfigs))
	}
	return preset.Apply(base), nil
}

func printScanConfigs() {
	log.Println("built-in scan configurations (-scan-config NAME):")
	for _, c := range scanner.BuiltInConfigs {
		log.Printf("  %s", c.Name)
		for _, k := range c.Keys() {
			if k.Set {
				log.Printf("      %-42s = %-5d  %s", k.Name, k.Value, k.What)
			} else {
				log.Printf("      %-42s   unset  (inherits the default)", k.Name)
			}
		}
	}
	log.Printf("\n%d of the %d configurations Burp ships set a key this engine implements.",
		len(scanner.BuiltInConfigs), scanner.BurpShippedConfigCount)
}
