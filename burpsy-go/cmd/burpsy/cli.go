package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/organizer"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/sequencer"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"github.com/burpsy-go/burpsy/internal/upstream"
	"go.uber.org/zap"
)

// The CLI is a direct engine driver: every subcommand below exercises the same
// packages the web UI routes to, without going through HTTP. This is the
// answer to "should the CLI talk to the web API" — it should not, because the
// engines are the source of truth and the HTTP layer is only one consumer.
//
// Invocation: `burpsy <command> [flags]`. Global server flags still parse
// first, so `burpsy -capture-dir DIR history` works; the subcommand is the
// first positional argument.

// cliCommand is one CLI subcommand.
type cliCommand struct {
	name  string
	usage string
	run   func(ctx *cliContext, args []string) error
}

// cliContext carries the engines every command shares. It is built once per
// invocation, mirroring the wiring in main()'s server mode.
type cliContext struct {
	store     *core.TrafficStore
	scope     *core.Scope
	logger    *zap.Logger
	findings  *core.FindingStore
	sess      *session.Coordinator
	intruder  *intruder.Intruder
	scanner   *scanner.ActiveScanner
	mr        *matchreplace.RuleSet
	toolLog   *toollog.ToolLog
	organizer *organizer.Store
	sequencer *sequencer.TokenList
	sender    *sender.Sender
	out       io.Writer

	// toolAllowlist is the parsed -tools map. It is kept on the context as well
	// as being folded into the bcheck tool runner because `extscan` resolves the
	// same allowlist for a different purpose: bchecks run a tool per insertion
	// point, extscan delegates a whole scan phase to one. One flag, one
	// allowlist, two consumers — an operator who has not named ffuf or nuclei
	// there cannot reach them from either.
	toolAllowlist map[string]string

	// dbPath is the -db SQLite file backing every store; empty means the CLI
	// behaves like the web UI without persistence (in-memory only). persist is
	// the open handle, nil when dbPath is empty.
	dbPath  string
	persist *persist.Store
}

// cliCommands is the dispatch table. main() routes here when the first
// positional argument names one of these.
var cliCommands = map[string]*cliCommand{}

func registerCLI(cmds ...*cliCommand) {
	for _, c := range cmds {
		cliCommands[c.name] = c
	}
}

// newCLIContext wires the engines a subcommand can touch. captureDir drives
// the store the same way the proxy's -capture-dir flag does; scope starts from
// any -scope-include/-scope-exclude given at launch. bchecksDir, when set,
// loads the corpus the same way the server path does, so `burpsy -bchecks DIR
// scan audit` dispatches the corpus's active checks and `scan live` sees the
// same passive set the proxy would run. tools is the -tools allowlist (name=path,
// comma-separated) for `run tool` statements; empty keeps tool checks counted
// but excluded from the audit set.
func newCLIContext(captureDir string, segmentBytes uint64, scopeInclude, scopeExclude, dbFile, bchecksDir, tools, dom string, upstreamPolicy *upstream.Policy) (*cliContext, error) {
	// Before the store is opened: a -dom that names nothing resolvable is refused here rather than
	// at the first DOM check, where it would read as a scan that found nothing.
	domOpts, domErr := domEngineOptions(dom)
	if domErr != nil {
		return nil, domErr
	}
	logger := zap.NewNop()
	var store *core.TrafficStore
	var err error
	if captureDir != "" {
		store, err = core.NewTrafficStoreWithCaptureDir(captureDir, segmentBytes)
	} else {
		store = core.NewTrafficStore()
	}
	if err != nil {
		return nil, fmt.Errorf("open capture store: %w", err)
	}
	scope := core.NewScope()
	if scopeInclude != "" {
		scope.AddInclude(scopeInclude)
	}
	if scopeExclude != "" {
		scope.AddExclude(scopeExclude)
	}
	// The corpus is loaded here, before the context literal, so a -bchecks
	// directory that will not load is a construction error — the CLI refuses to
	// run a scan under half its checks, exactly as the server path refuses to
	// start. The web path wires the same LoadDir's ActiveChecks, so the two
	// surfaces cannot disagree about which corpus is in force.
	var corpusChecks []*bcheck.Check
	if bchecksDir != "" {
		ps, lerr := scanner.LoadDir(bchecksDir, store, scope, logger)
		if lerr != nil {
			return nil, fmt.Errorf("load bchecks from %s: %w", bchecksDir, lerr)
		}
		corpusChecks = ps.ActiveChecks()
		logger.Info("bchecks loaded", zap.String("dir", bchecksDir), zap.String("report", ps.Report().Summary()))
	}
	bundledChecks, berr := bundledCorpus(logger)
	if berr != nil {
		return nil, berr
	}
	senderCfg := sender.DefaultSenderConfig()
	// Every sender this context builds — the repeater, the intruder's per-request senders and the
	// active scanner's — shares the one policy, so -upstream-proxy covers the CLI's egress as
	// completely as it covers the server's. Nil is the ordinary unconfigured case and dials directly.
	senderCfg.Upstream = upstreamPolicy
	// The -tools allowlist becomes a runner only if something was configured. A malformed entry
	// refuses construction here, before any scan — a typo must not surface mid-scan as checks
	// that silently cannot run. Nil keeps tool checks counted-but-excluded (see
	// scanner.corpusActiveChecks).
	toolAllowlist, terr := parseToolAllowlist(tools)
	if terr != nil {
		return nil, terr
	}
	var toolRunner bcheck.ToolRunner
	if toolAllowlist != nil {
		toolRunner = scanner.NewToolRunner(scanner.ToolRunnerConfig{Tools: toolAllowlist})
	}
	ctx := &cliContext{
		store:  store,
		scope:  scope,
		logger: logger,
		// SetDedupPolicy below rather than at construction because core cannot import scanner; see
		// scanner.DedupPolicy. Without it the CLI would still dedup, just per path for every row.
		findings: core.NewFindingStore(),
		sess:     session.NewCoordinator(logger),
		// WithSend, because the engine has no other way out and refuses to send without one. It used
		// to dial targets itself with no scope check at all, which made `intruder run` the one CLI
		// surface that ignored -scope-include entirely. A fresh AuthorisedSender per request rather
		// than one per run: a payload spliced into a path position rewrites the request line, so the
		// authority has to be re-judged against the bytes each time.
		intruder: intruder.NewIntruder(logger).WithSend(
			func(c context.Context, host string, port uint16, tls bool, raw []byte) ([]byte, error) {
				sent, err := sender.NewAuthorisedSender(scope, sender.NewSender(senderCfg), host, port, tls).Send(c, raw)
				if err != nil {
					return nil, err
				}
				return sent.Raw, nil
			}),
		// WithScope, so the audit engine refuses an out-of-scope exchange before it plans any work
		// and refuses any probe whose own URL leaves the engagement. The capability recipe is the
		// shared one (internal/scanner/wiring.go): ledgers, JS-library and JWT checks construct
		// by default; the tool runner carries the -tools allowlist (nil keeps tool checks
		// counted-but-excluded); the corpus checks are a no-op when no corpus was loaded, so the
		// built-in table is the whole set then. The session coordinator is ctx.sess itself,
		// attached below — the same single-handle rule as Scope — so the session rules the CLI
		// edits govern the scanner's comparisons too.
		scanner: scanner.NewActiveScanner(store, logger).
			WithSender(sender.NewSender(senderCfg)).
			WithScope(scope).
			WithCapabilities(scanner.CapabilityWiring{
				CorpusChecks:  corpusChecks,
				BundledCorpus: bundledChecks,
				ToolRunner:    toolRunner,
			}),
		mr:        matchreplace.NewRuleSet(),
		toolLog:   toollog.New(),
		organizer: organizer.New(),
		sequencer: sequencer.NewTokenList(),
		sender:    sender.NewSender(senderCfg),
		out:       os.Stdout,
		dbPath:    dbFile,

		toolAllowlist: toolAllowlist,
	}
	// The provider is lazy, so naming an engine costs nothing until a DOM check asks for it; a scan
	// with no DOM-based check in its set never starts a browser at all.
	if domOpts != nil {
		ctx.scanner.WithBrowserProvider(scanner.NewLazyBrowserProvider(*domOpts))
	}
	// The session coordinator is attached here rather than in the literal above because ctx.sess
	// does not exist yet inside it. Sharing the CLI's instance — not a copy — is the same
	// single-handle rule as Scope: session rules the CLI edits govern the scanner's
	// access-control and CSRF comparisons too.
	ctx.scanner.WithSessionCoordinator(ctx.sess)
	// Before loadState, which restores persisted findings: SetDedupPolicy rebuilds the index anyway,
	// but installing it first means the restore builds the right keys the first time.
	ctx.findings.SetDedupPolicy(scanner.DedupPolicy())
	if err := ctx.loadState(); err != nil {
		return nil, err
	}
	return ctx, nil
}

// runCLI dispatches to a subcommand and exits. Returns the process exit code.
func runCLI(name string, args []string, captureDir string, segmentBytes uint64, scopeInclude, scopeExclude, dbFile, bchecksDir, tools, dom string, upstreamPolicy *upstream.Policy) int {
	if name == "help" || name == "-h" || name == "--help" {
		printCLIHelp()
		return 0
	}
	cmd, ok := cliCommands[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "burpsy: unknown command %q (see \"burpsy help\")\n", name)
		return 2
	}
	ctx, err := newCLIContext(captureDir, segmentBytes, scopeInclude, scopeExclude, dbFile, bchecksDir, tools, dom, upstreamPolicy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "burpsy: %v\n", err)
		return 1
	}
	if err := cmd.run(ctx, args); err != nil {
		fmt.Fprintf(os.Stderr, "burpsy %s: %v\n", name, err)
		return 1
	}
	return 0
}

func printCLIHelp() {
	fmt.Println("usage: burpsy [server flags] <command> [command flags]")
	fmt.Println()
	fmt.Println("Server mode (default, no command): run the proxy and web UI.")
	fmt.Println("Server flags: -proxy -web -capture-dir -scope-include -scope-exclude",
		"-intercept-tls -ca-dir -segment-bytes -tls-passthrough -tls-passthrough-port",
		"-tls-defaults -store-verify -bchecks -tools -upstream-proxy -upstream-proxy-rule")
	fmt.Println()
	fmt.Println("Commands (drive engines directly, no HTTP):")
	fmt.Println()
	for _, name := range sortedCLINames() {
		fmt.Printf("  %-22s %s\n", name, cliCommands[name].usage)
	}
}

func sortedCLINames() []string {
	names := make([]string, 0, len(cliCommands))
	for n := range cliCommands {
		names = append(names, n)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}

// parseToolAllowlist turns the -tools flag value (name=path,name=path) into the
// allowlist map the scanner's runner gates `run tool` against. Empty string
// yields nil (no runner). A malformed entry is an error — a typo in a name or
// path must refuse construction, not surface mid-scan as a tool that never ran.
func parseToolAllowlist(s string) (map[string]string, error) {
	return parseNamePathAllowlist("-tools", s)
}

// parseNamePathAllowlist is the shared name=path,name=path parser behind -tools and -plugins.
//
// One parser because the two flags are the same decision made twice: which executables on this machine
// may this process run. Sharing it means a fix to the format (a trimmed space, a rejected duplicate)
// cannot land for one flag and not the other. The flag name is threaded through only so the error names
// the flag the operator actually typed.
func parseNamePathAllowlist(flagName, s string) (map[string]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, path, ok := strings.Cut(pair, "=")
		name, path = strings.TrimSpace(name), strings.TrimSpace(path)
		if !ok || name == "" || path == "" {
			return nil, fmt.Errorf("bad %s entry %q: want name=path", flagName, pair)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("duplicate %s entry %q", flagName, name)
		}
		out[name] = path
	}
	return out, nil
}

// newFlagSet is a tiny wrapper so commands can parse their own flags.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// printJSON writes v as indented JSON to the context's writer.
func printJSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// printText writes a plain line (single trailing newline) to the writer.
func printText(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, format+"\n", a...)
}

// readInput loads a value that may be a literal, "@path" (read file), or "-"
// (read stdin). It is the shared convention for -raw / -request flags.
func readInput(v string) ([]byte, error) {
	switch {
	case v == "-":
		return io.ReadAll(os.Stdin)
	case strings.HasPrefix(v, "@"):
		data, err := os.ReadFile(strings.TrimPrefix(v, "@"))
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", strings.TrimPrefix(v, "@"), err)
		}
		return data, nil
	default:
		return []byte(v), nil
	}
}

// resolveHostPort splits a host:port target, defaulting the port to 80 (or 443
// when tls is set). The sender and intruder both need explicit host+port.
func resolveHostPort(target string, tls bool) (string, uint16, error) {
	host := target
	port := uint16(80)
	if tls {
		port = 443
	}
	if i := strings.LastIndex(target, ":"); i >= 0 {
		host = target[:i]
		p, err := parseIntPort(target[i+1:])
		if err != nil {
			return "", 0, fmt.Errorf("invalid port in %q", target)
		}
		port = p
	}
	if host == "" {
		return "", 0, fmt.Errorf("empty host in target %q", target)
	}
	return host, port, nil
}

func parseIntPort(s string) (uint16, error) {
	var p uint16
	if _, err := fmt.Sscanf(s, "%d", &p); err != nil || p == 0 {
		return 0, fmt.Errorf("not a port: %q", s)
	}
	return p, nil
}

// runWithTimeout wraps ctx with a timeout for network-bound commands.
func runWithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}

// hostOf returns the host portion of a host:port exchange field (already
// host-only in core.Exchange), for display padding.
func hostOf(h string) string {
	return h
}
