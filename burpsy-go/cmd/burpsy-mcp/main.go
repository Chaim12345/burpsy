// Command burpsy-mcp serves a running burpsy console over the Model Context Protocol (stdio).
//
// It is a separate binary rather than a `burpsy mcp` subcommand for one reason: every subcommand of
// cmd/burpsy is dispatched through newCLIContext, which opens the traffic store, loads the bcheck
// corpus and builds the scanners before the command runs — a second engine wired against the same
// database, built only to make HTTP calls to the first. An MCP transport needs none of it, and
// paying for it would mean the transport's correctness depended on engine wiring it never uses.
// The console's own API is untouched either way, which is what the bead requires.
//
// Usage: an MCP host runs this with an absolute path and points it at the console:
//
//	burpsy-mcp -web http://127.0.0.1:8081
//
// stdout carries JSON-RPC and nothing else; every diagnostic goes to stderr, because a stray line
// on stdout corrupts the stream.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/burpsy-go/burpsy/internal/buildinfo"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/burpsy-go/burpsy/internal/mcp"
)

func main() {
	webAddr := flag.String("web", "http://127.0.0.1:8081",
		"base URL of the running burpsy console (a bare host:port is accepted and assumed http)")
	timeout := flag.Duration("timeout", 10*time.Minute,
		"how long one tool call may take before the transport gives up on the console")
	list := flag.Bool("list", false,
		"print the tool surface this binary would expose and exit (does not speak stdio)")
	surface := flag.String("surface", string(mcp.SurfaceGrouped),
		"tool surface to publish: \"grouped\" (capability-grouped tools, the default) or \"routes\" (one tool per manifest route, for debugging)")
	syncWindow := flag.Duration("sync-window", 15*time.Second,
		"how long a call that started a console task (an audit, a crawl) waits for it before answering with a task handle")
	noNotify := flag.Bool("no-notifications", false,
		"do not push task completion and High/Critical issues as notifications/message")
	showVersion := flag.Bool("version", false, "print the version and exit")
	only := flag.String("only", "", "comma-separated tool names to publish (default: all); burpsy_confirm and burpsy_task_status always stay")
	flag.Parse()

	if *showVersion {
		fmt.Printf("burpsy-mcp %s\n", version())
		return
	}

	// The manifest is read locally — it is compiled into this binary — so the tool surface can be
	// printed without a console running. That is the point of -list: an operator can see what an
	// assistant would be handed before wiring it to anything.
	srv, err := mcp.New(mcp.Options{
		BaseURL:         *webAddr,
		Timeout:         *timeout,
		Surface:         mcp.Surface(*surface),
		SyncWindow:      *syncWindow,
		NoNotifications: *noNotify,
		Only:            splitOnly(*only),
	})
	if err != nil {
		fatal(err)
	}

	if *list {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"console": srv.BaseURL(), "surface": srv.Surface(), "routes": srv.RouteCount(),
			"tools": srv.ToolNames(),
		}); err != nil {
			fatal(err)
		}
		return
	}

	// A best-effort reachability note on stderr. Not fatal: an MCP host may start this before the
	// console, and a transport that refused to start would be a host configuration problem
	// reported as a crash.
	fmt.Fprintf(os.Stderr, "burpsy-mcp %s: console %s, %s surface: %d tools over %d manifest routes\n",
		version(), srv.BaseURL(), srv.Surface(), srv.ToolCount(), srv.RouteCount())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Serve(ctx); err != nil && ctx.Err() == nil {
		fatal(err)
	}
}

// version reports the stamped release version, else the module version, else "dev".
func version() string { return buildinfo.String() }

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "burpsy-mcp: %v\n", err)
	os.Exit(1)
}

// splitOnly reads the -only flag: comma-separated names, blanks dropped; nil for an empty flag.
func splitOnly(v string) []string {
	var out []string
	for _, n := range strings.Split(v, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}
