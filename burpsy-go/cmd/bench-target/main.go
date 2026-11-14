// bench-target serves vulnapp plus an /all index linking every manifest path so crawlers of any tool see the same link graph. Benchmark tooling, not shipped.
package main

import (
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"

	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9100", "bind address")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/all", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>all endpoints</h1>\n")
		for _, e := range vulnapp.Vulnerabilities() {
			p := e.Path
			if i := strings.Index(p, "?"); i >= 0 {
				p = p[:i]
			}
			fmt.Fprintf(w, "<a href=\"%s\">%s</a><br>\n", html.EscapeString(e.Path), html.EscapeString(p))
		}
		fmt.Fprint(w, "</body></html>")
	})
	mux.Handle("/", vulnapp.Handler())
	log.Printf("bench target on http://%s (index /all)", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
