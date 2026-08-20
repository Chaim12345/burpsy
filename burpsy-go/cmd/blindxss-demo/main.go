// Command blindxss-demo is a manual-testing scratch tool, not a shipped subcommand: it
// starts internal/blindxss's listener on a fixed local port, mints one payload, prints
// the script tag to plant, and polls for hits until killed. Not wired into cmd/burpsy.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/burpsy-go/burpsy/internal/blindxss"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8899", "listen address")
	baseURL := flag.String("base-url", "", "externally reachable base URL (defaults to http://<addr>)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	l, err := blindxss.NewListener(ctx, blindxss.Options{Addr: *addr, BaseURL: *baseURL})
	if err != nil {
		fmt.Fprintln(os.Stderr, "bind failed:", err)
		os.Exit(1)
	}
	defer l.Close()

	payload, err := l.GeneratePayload()
	if err != nil {
		fmt.Fprintln(os.Stderr, "GeneratePayload failed:", err)
		os.Exit(1)
	}

	fmt.Println("blindxss-demo listening on", l.Addr().String())
	fmt.Println("base URL:              ", l.BaseURL())
	fmt.Println("token:                 ", payload.Token)
	fmt.Println("script URL:            ", payload.ScriptURL)
	fmt.Println("plant this:            ", payload.ScriptTag())
	fmt.Println()
	fmt.Println("open the script URL directly in a browser tab, or embed the tag in a test page.")
	fmt.Println("polling for hits every 2s, printing each new one as JSON. Ctrl-C to stop.")
	fmt.Println()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	seen := 0
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			fmt.Println("shutting down")
			return
		case <-ticker.C:
			hits, err := l.HitsFor(payload.Token)
			if err != nil {
				fmt.Fprintln(os.Stderr, "HitsFor error:", err)
				continue
			}
			for _, h := range hits[seen:] {
				b, _ := json.MarshalIndent(h, "", "  ")
				fmt.Println("HIT:")
				fmt.Println(string(b))
			}
			seen = len(hits)
		}
	}
}
