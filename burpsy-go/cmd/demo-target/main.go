// demo-target runs the deliberately vulnerable application from internal/vulnapp for manual
// work: pointing a browser at it, driving the proxy by hand, or watching a scan happen.
//
// The handlers deliberately do not live here. They moved to internal/vulnapp so that
// internal/scanner's runtime test can start the same application in-process and assert the
// scanner actually reports what the target exposes. Two copies of a vulnerable app would drift,
// and the copy the tests did not use would be the one that lied.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "bind address")
	flag.Parse()

	fmt.Printf("demo target on http://%s\n", *addr)
	// Endpoints on a listener of their own (request smuggling's two-tier targets) are not routes on
	// the shared server; each listener is started on a loopback port and its URL printed instead.
	listeners := map[string]*vulnapp.Listener{}
	for _, e := range vulnapp.Vulnerabilities() {
		kind := "VULNERABLE"
		switch {
		case e.Row == "":
			kind = "support   "
		case e.Safe:
			kind = "safe      "
		}
		method := e.Method
		if method == "" {
			method = "GET"
		}
		if e.Listener != "" {
			l := listeners[e.Listener]
			if l == nil {
				var err error
				if l, err = vulnapp.StartListener(e.Listener); err != nil {
					log.Fatalf("start listener %s: %v", e.Listener, err)
				}
				listeners[e.Listener] = l
			}
			fmt.Printf("  %s %-6s %-34s %s (on %s)\n", kind, method, e.Path, e.Row, l.URL())
			continue
		}
		fmt.Printf("  %s %-6s %-34s %s\n", kind, method, e.Path, e.Row)
	}
	log.Fatal(http.ListenAndServe(*addr, vulnapp.Handler()))
}
