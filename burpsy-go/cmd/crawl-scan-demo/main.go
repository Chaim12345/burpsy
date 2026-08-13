// Command crawl-scan-demo starts a small vulnerable HTTP server, crawls it
// with internal/crawler, then runs the real ActiveScanner (SQL injection and
// reflected XSS) against everything the crawl captured — proving the
// checkSQLi/checkXSS evidence models fire against real requests and real
// responses, not just the pure-function unit tests in sqli_test.go/xss_test.go.
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

	srv := &http.Server{Handler: vulnerableMux()}
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
		Seeds:  []string{base + "/", base + "/products?id=1", base + "/account"},
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

// vulnerableMux is a self-contained copy of the demo target's newly added
// SQLi/XSS endpoints (cmd/demo-target is its own module and cannot be
// imported here), kept behaviorally identical so this program demonstrates
// the same surface the standalone demo target exposes.
func vulnerableMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>
			<a href="/products?id=1">Products</a>
			<a href="/account?xss=seed">Account</a>
		</body></html>`)
	})
	mux.HandleFunc("/products", productsHandler)
	mux.HandleFunc("/account", accountHandler)
	return mux
}

func productsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	for _, values := range r.URL.Query() {
		for _, v := range values {
			unescaped := strings.ReplaceAll(v, "''", "")
			quoteCount := strings.Count(unescaped, "'")
			lower := strings.ToLower(v)

			switch {
			case strings.Contains(lower, "order by 999"):
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "SQL error: Unknown column '999' in 'order clause'")
				return
			case strings.Contains(lower, "order by 1"):
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "Products (sorted): Widget, Gadget, Gizmo")
				return
			case strings.Contains(lower, "or '1'='1"):
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "Products: Widget, Gadget, Gizmo, Doohickey, Thingamajig")
				return
			case strings.Contains(lower, "and '1'='2"):
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "No products found")
				return
			case quoteCount > 0:
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "SQL syntax error: you have an error in your SQL syntax near '%s' at line 1", v)
				return
			}
		}
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Products: Widget, Gadget, Gizmo")
}

func accountHandler(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("xss")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><body>
	<div data-value="%s">Account settings</div>
	<script>var lastSearch = '%s';</script>
</body></html>`, value, value)
}
