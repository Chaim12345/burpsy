package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"burpsy-go/pkg/intruder"
	"burpsy-go/pkg/proxy"
	"burpsy-go/pkg/repeater"
	"burpsy-go/pkg/scope"
	"burpsy-go/pkg/sitemap"
	"burpsy-go/pkg/store"
	"burpsy-go/pkg/web"
)

type scopeList []string

func (s *scopeList) String() string {
	return fmt.Sprintf("%v", []string(*s))
}

func (s *scopeList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	var proxyBind string
	var webBind string
	var caDir string
	var interceptTLS bool
	var includes scopeList
	var excludes scopeList

	flag.StringVar(&proxyBind, "proxy", "127.0.0.1:8080", "address to bind proxy listener to")
	flag.StringVar(&webBind, "web", "127.0.0.1:8081", "address to bind web server to")
	flag.StringVar(&caDir, "ca-dir", "", "directory to load/generate Root CA")
	flag.BoolVar(&interceptTLS, "intercept-tls", false, "enable TLS decryption/decryption")
	flag.Var(&includes, "scope-include", "host pattern to include in scope (repeatable)")
	flag.Var(&excludes, "scope-exclude", "host pattern to exclude from scope (repeatable)")

	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("Starting burpsy Go optimized port...")

	// 1. Initialize Store & Scope
	trafficStore := store.NewTrafficStore()
	scopeEngine := scope.NewScope()

	if len(includes) == 0 && len(excludes) == 0 {
		// Default to allow all if no constraints provided
		scopeEngine = scope.NewAllowEverythingScope()
	} else {
		for _, inc := range includes {
			scopeEngine.AddRule(scope.NewIncludeRule(inc))
		}
		for _, exc := range excludes {
			scopeEngine.AddRule(scope.NewExcludeRule(exc))
		}
	}

	// 2. Load or generate Certificate Authority
	if caDir == "" {
		home, _ := os.UserHomeDir()
		if home == "" {
			home = "."
		}
		caDir = filepath.Join(home, ".burpsy-go", "ca")
	}

	var caEngine *proxy.CertAuthority
	var caPem string
	var err error

	if interceptTLS {
		caEngine, err = proxy.LoadOrGenerateCA(caDir)
		if err != nil {
			log.Fatalf("Fatal: failed to load or generate CA: %v", err)
		}
		// Load caCert bytes to serve over /ca.crt
		certBytes, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
		if err == nil {
			caPem = string(certBytes)
		}
	}

	// 3. Initialize Proxy & services
	policy := proxy.NewTlsPolicy()
	pr := proxy.NewProxy(proxyBind, trafficStore, scopeEngine, caEngine, policy, interceptTLS)

	repService := repeater.NewRepeater(trafficStore)
	intrService := intruder.NewIntruder(trafficStore)
	sitemapService := sitemap.NewSitemap(trafficStore)

	// 4. Initialize Web server
	webServer := web.NewServer(webBind, trafficStore, scopeEngine, caPem)
	webServer.Repeater = repService
	webServer.Intruder = intrService
	webServer.Sitemap = sitemapService

	// Share the exact same Interceptor and MatchReplaceStore!
	webServer.Interceptor = pr.Interceptor
	webServer.MRStore = pr.MRStore

	// 5. Start Proxy
	err = pr.Start()
	if err != nil {
		log.Fatalf("Fatal: failed to start proxy: %v", err)
	}
	log.Printf("Proxy intercepting on %s", proxyBind)

	// 6. Start Web server (blocking)
	go func() {
		err = webServer.Start()
		if err != nil {
			log.Fatalf("Fatal: failed to start web server: %v", err)
		}
	}()

	// Wait for terminate signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	log.Printf("Shutting down gracefully...")
	pr.Close()
	log.Printf("Stopped.")
}
