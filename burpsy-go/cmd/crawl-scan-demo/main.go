// Command crawl-scan-demo starts the vulnerable application from internal/vulnapp, crawls it with
// internal/crawler, then runs the real ActiveScanner against everything the crawl captured — so the
// SQL-injection and reflected-XSS evidence models are exercised against real requests and real
// responses rather than only the pure-function unit tests.
//
// It used to carry its own copy of the vulnerable endpoints, justified in a comment by
// "cmd/demo-target is its own module and cannot be imported here". That was true when demo-target
// had a nested go.mod and is not any more, and the copy had already drifted: it kept branching on
// the scanner's own probe strings after internal/vulnapp stopped doing so. A second vulnerable
// target that nobody tests is a target that quietly disagrees with the one that matters, so the
// seeds now come from vulnapp's manifest and the handler is vulnapp's.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/crawler"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: vulnapp.Handler()}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.ParseUint(portStr, 10, 16)
	base := "http://" + ln.Addr().String()
	fmt.Printf("demo target listening on %s\n", base)

	store := core.NewTrafficStore()
	scope := core.NewScopeAllowEverything()
	snd := sender.NewSender(sender.DefaultSenderConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	crawlCfg := crawler.Config{
		Seeds:  vulnappSeeds(base),
		Scope:  scope,
		Sender: snd,
		Capture: scanner.Capture{
			Store: store,
		},
		Limits: crawler.Limits{
			MaxRequests: 25,
			MaxDepth:    2,
		},
	}
	c, err := crawler.New(crawlCfg)
	if err != nil {
		return fmt.Errorf("crawler.New: %w", err)
	}
	report := c.Run(ctx)
	fmt.Println("--- crawl report ---")
	fmt.Println(report.Summary())

	exchanges := store.Exchanges()
	fmt.Printf("captured %d exchange(s) for host %s:%d\n", len(exchanges), host, port)
	for _, ex := range exchanges {
		fmt.Printf("  exchange %d: %s %s\n", ex.ID, ex.Method, ex.Path)
	}

	logger := zap.NewNop()
	scan := scanner.NewActiveScanner(store, logger).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&scanner.ScanConfig{
			MaxConcurrency:     4,
			Timeout:            15 * time.Second,
			CheckSqli:          true,
			CheckXss:           true,
			CheckPathTraversal: false,
			CheckSSRF:          false,
			CheckXXE:           false,
			CheckJwtWeak:       false,
			CheckJSVulns:       false,
		})

	ids := make([]core.ExchangeID, 0, len(exchanges))
	for _, ex := range exchanges {
		ids = append(ids, ex.ID)
	}
	findings, err := scan.AuditMultiple(ctx, ids)
	if err != nil {
		return fmt.Errorf("AuditMultiple: %w", err)
	}

	fmt.Println("--- active scan findings ---")
	if len(findings) == 0 {
		fmt.Println("no findings")
	}
	sawSQLi, sawXSS := false, false
	for _, f := range findings {
		fmt.Printf("[%s] %s %s %s\n  evidence: %s\n", f.Severity, f.Name, f.Method, f.URL, f.Evidence)
		if strings.HasPrefix(f.Name, "SQL injection") {
			sawSQLi = true
		}
		if strings.Contains(f.Name, "Cross-site scripting") {
			sawXSS = true
		}
	}

	fmt.Println("--- verdict ---")
	fmt.Printf("SQLi detected and reported: %v\n", sawSQLi)
	fmt.Printf("XSS detected and reported:  %v\n", sawXSS)
	if !sawSQLi || !sawXSS {
		os.Exit(1)
	}
	return nil
}

// vulnappSeeds returns one crawl seed per endpoint the manifest declares vulnerable.
//
// Seeding from the manifest rather than from a hand-written list means this program cannot drift
// away from the corpus internal/scanner tests against: an endpoint added there is crawled here on
// the next build. Safe counterparts are included too — they are part of the surface, and a crawl
// that skipped them would not represent a real one.
func vulnappSeeds(base string) []string {
	seeds := []string{base + "/"}
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Path == "/" || e.Method == http.MethodPost {
			// The crawler issues GETs; a POST-only row is reached by form submission, which is the
			// crawler's own business and not something a seed can express.
			continue
		}
		seeds = append(seeds, base+e.Path)
	}
	return seeds
}
