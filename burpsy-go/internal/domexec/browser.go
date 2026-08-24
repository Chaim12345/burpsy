// Package domexec provides a headless-Chrome DOM taint-observation harness for
// scanner checks that cannot be answered from the raw HTTP exchange alone.
//
// # Why this package exists
//
// About forty of the declined catalog rows (XSS DOM-based, open redirection
// DOM-based, WebSocket URL poisoning, HTML5 storage manipulation, document
// domain manipulation, cookie manipulation, client-side SQL/XPath/JSON
// injection, DOM data manipulation, link manipulation, denial of service)
// share one decline reason: they need a headless browser / JavaScript
// execution engine to observe runtime DOM sinks and sources fed by request or
// stored data. The HTTP-only scanner sees bytes on the wire; it cannot see
// what a page's own script does with those bytes after the parser and the
// script engine run. This package supplies that missing runtime.
//
// The approach is a taint harness, not a payload library: it plants a canary
// in a chosen controllable DOM source (URL hash, URL search, referrer,
// window.name, or an incoming postMessage), loads the page under a real
// Chrome instance with the canary in place, and reports every dangerous sink
// call whose argument contained the canary. Whether a given canary constitutes
// an exploitable payload for a specific check is the caller's decision; this
// package only answers "did attacker-controlled data reach a dangerous sink at
// runtime", which is exactly the question the ~40 declined rows are blocked on.
//
// # The honest-failure contract
//
// If no Chrome binary can be found, or the browser process fails to start,
// NewBrowser returns an error naming what it looked for. A caller MUST
// surface that as "no DOM execution available" and MUST NOT report a clean
// (zero-finding) result — zero taint observations from a working browser and
// zero taint observations because there was no browser at all are different
// facts, and conflating them turns an untested page into an apparent absence
// of vulnerability. This is the same honest-counting rule internal/oob follows
// for its own missing-binary case.
//
// # What the instrumentation can and cannot see
//
// ObserveTaint only sees calls that pass through the specific set of sinks
// wrapped by instrumentationJS (see taint.go for the exact list and, just as
// importantly, for the one source/sink combination — bare `location = x` —
// that a JS-level property override provably cannot intercept in this Chrome
// build, and how that gap is closed instead). A page that reaches a dangerous
// sink through an API this harness does not wrap produces zero observations.
// That is a false negative, not proof of safety, and callers must not read it
// as "no DOM vulnerability here".
package domexec

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// chromeCandidates is the ordered list of binary names tried on PATH when
// Options.ChromePath is empty. These match the three binaries this project's
// containers are known to ship (chromium, google-chrome, google-chrome-stable);
// order is not meaningful beyond documenting what was tried on failure.
var chromeCandidates = []string{"chromium", "google-chrome", "google-chrome-stable"}

// Options configures a Browser.
type Options struct {
	// ChromePath, if set, is used verbatim instead of searching PATH. It may
	// be a bare name (resolved via exec.LookPath) or an absolute path.
	ChromePath string

	// RemoteURL, if set, attaches to an already-running CDP server (obscura
	// serve, lightpanda serve) instead of launching a browser process. This is
	// how an alternative engine plugs in: the server owns process lifetime, so
	// Close releases only this client's connection and never the server itself,
	// and Headless/UserAgent/ChromePath are meaningless here — the server was
	// configured before we connected. Setting both RemoteURL and ChromePath is
	// a configuration contradiction and is refused rather than silently
	// resolved by priority.
	RemoteURL string

	// Headed shows Chrome's window. The zero value is headless, which is the only mode that
	// works where there is no display server and the only one that does not steal focus from
	// whoever is running the tests.
	//
	// This is deliberately phrased as the opt-in rather than as `Headless bool`. That spelling
	// made a visible window the zero value, so every Options{} literal in the test suite
	// silently launched one; the field's own comment had to ask callers to remember to set it,
	// which is an API telling you it is shaped wrong. Set this only to watch a flow live.
	Headed bool

	// Timeout bounds every page operation (navigation, script evaluation,
	// settle wait). Zero means "use the default": a hostile or slow page
	// must not be able to hang a scan indefinitely. Default 30s.
	Timeout time.Duration

	// UserAgent overrides Chrome's default User-Agent header when non-empty.
	UserAgent string
}

// resolvedTimeout returns opts.Timeout, or the 30s default when unset.
func (o Options) resolvedTimeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return 30 * time.Second
}

// resolveChromePath finds the Chrome/Chromium binary to launch.
//
// An explicit path that does not resolve to an executable is reported by
// name, not silently ignored in favour of a PATH search — a caller who
// configured a specific binary and got a typo deserves to know that, not to
// have this package quietly fall back to whatever else is on PATH.
func resolveChromePath(explicit string) (string, error) {
	if explicit != "" {
		p, err := exec.LookPath(explicit)
		if err != nil {
			return "", fmt.Errorf("domexec: configured chrome path %q is not executable: %w", explicit, err)
		}
		return p, nil
	}
	for _, name := range chromeCandidates {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("domexec: no chrome binary found; looked for %s on PATH", strings.Join(chromeCandidates, ", "))
}

// Browser owns one headless Chrome process and the chromedp allocator and
// browser contexts backing it. Callers get a new isolated tab per observation
// (see taint.go) so concurrent or sequential ObserveTaint/RenderedDOM calls
// never see each other's instrumentation state.
type Browser struct {
	allocCtx      context.Context
	allocCancel   context.CancelFunc
	browserCtx    context.Context
	browserCancel context.CancelFunc

	opts Options

	// remoteURL is set only in remote mode. The server owns process lifetime,
	// and its per-connection isolation (each CDP connection gets its own V8
	// isolate) is what lets every check dial a fresh connection instead of
	// sharing one: see newTab.
	remoteURL string

	closeOnce sync.Once
}

// NewBrowser starts or attaches to a browser and blocks until it is actually
// usable (not merely until a process handle or socket exists — chromedp's
// allocators start lazily on first use, so this issues a no-op Run to force
// that and catch startup failures here rather than on the caller's first real
// operation).
//
// Two modes, mutually exclusive (setting both is an error):
//
//   - exec (default): resolves a Chrome binary per Options.ChromePath and
//     launches it.
//   - remote (Options.RemoteURL): attaches to a running CDP server such as
//     `obscura serve` or `lightpanda serve`. The server owns process lifetime;
//     Close releases only this client's connection.
//
// NoSandbox is required in the flag set below because this scanner commonly
// runs as root inside a container: Chrome's sandbox refuses to initialise for
// a root user and the process exits immediately without it.
func NewBrowser(ctx context.Context, opts Options) (*Browser, error) {
	if opts.RemoteURL != "" && opts.ChromePath != "" {
		return nil, errors.New("domexec: RemoteURL and ChromePath are mutually exclusive: one names a running CDP server, the other a binary to launch")
	}

	timeout := opts.resolvedTimeout()

	var allocCtx context.Context
	var allocCancel context.CancelFunc
	var describe string

	if opts.RemoteURL != "" {
		// Remote mode: attach to an already-running CDP server. The warm-up Run
		// below still applies — it proves the server accepts a browser session
		// and answers protocol calls before the caller commits to it.
		describe = opts.RemoteURL
		allocCtx, allocCancel = chromedp.NewRemoteAllocator(ctx, opts.RemoteURL)
	} else {
		path, err := resolveChromePath(opts.ChromePath)
		if err != nil {
			return nil, err
		}
		describe = path

		execOpts := []chromedp.ExecAllocatorOption{
			chromedp.ExecPath(path),
			chromedp.NoSandbox,
			chromedp.DisableGPU,
			// The rest mirror chromedp.DefaultExecAllocatorOptions - itself "Puppeteer's default
			// behavior" - which NewExecAllocator does NOT apply on its own; that convenience is
			// wired into chromedp's zero-config NewContext path only, so building execOpts from a
			// bare ExecPath/NoSandbox/DisableGPU set, as this function did before, paid for
			// Chrome's full first-run/update/telemetry machinery on every one of this harness's
			// ~17 launches: a first-run dialog check, a default-browser prompt, background
			// network probes for Safe Browsing and component updates, extension/sync bootstrap,
			// and an OS keychain lookup for the password store (which can stall for seconds, or
			// hang, on a container with no keyring daemon). None of it is observable to a page
			// under test - every flag below disables a Chrome-internal service, never a web
			// platform API a taint check could depend on - so it is free wall-clock time back.
			chromedp.NoFirstRun,
			chromedp.NoDefaultBrowserCheck,
			chromedp.Flag("disable-background-networking", true),
			chromedp.Flag("disable-background-timer-throttling", true),
			chromedp.Flag("disable-backgrounding-occluded-windows", true),
			chromedp.Flag("disable-breakpad", true),
			chromedp.Flag("disable-client-side-phishing-detection", true),
			chromedp.Flag("disable-default-apps", true),
			chromedp.Flag("disable-dev-shm-usage", true),
			chromedp.Flag("disable-extensions", true),
			chromedp.Flag("disable-hang-monitor", true),
			chromedp.Flag("disable-ipc-flooding-protection", true),
			chromedp.Flag("disable-prompt-on-repost", true),
			chromedp.Flag("disable-renderer-backgrounding", true),
			chromedp.Flag("disable-sync", true),
			chromedp.Flag("metrics-recording-only", true),
			chromedp.Flag("safebrowsing-disable-auto-update", true),
			chromedp.Flag("password-store", "basic"),
			chromedp.Flag("use-mock-keychain", true),
		}
		if !opts.Headed {
			execOpts = append(execOpts, chromedp.Headless)
		}
		if opts.UserAgent != "" {
			execOpts = append(execOpts, chromedp.UserAgent(opts.UserAgent))
		}

		allocCtx, allocCancel = chromedp.NewExecAllocator(ctx, execOpts...)
	}

	browserCtx, browserCancel := chromedp.NewContext(allocCtx)

	// Warm the browser up so a launch failure is reported here rather than at the first
	// ObserveTaint call.
	//
	// The startup bound deliberately does NOT come from a context derived from browserCtx.
	// An earlier revision used `startCtx, cancel := context.WithTimeout(browserCtx, timeout)`
	// with `defer cancel()`, which tore the browser down the instant NewBrowser returned:
	// chromedp allocates the browser against the context the first Run is given, so
	// cancelling that context closes the browser even though browserCtx itself is still
	// live. Every subsequent call then failed with "context canceled" while NewBrowser had
	// reported success — the worst shape of failure, since a caller would read it as a
	// working browser producing no findings. The bound is therefore a timer beside the Run,
	// and the only thing that cancels browserCtx is a genuine failure or Close.
	runErr := make(chan error, 1)
	go func() { runErr <- chromedp.Run(browserCtx) }()
	select {
	case err := <-runErr:
		if err != nil {
			browserCancel()
			allocCancel()
			return nil, fmt.Errorf("domexec: browser at %q failed to start: %w", describe, err)
		}
	case <-time.After(timeout):
		browserCancel()
		allocCancel()
		return nil, fmt.Errorf("domexec: browser at %q did not become ready within %s", describe, timeout)
	}

	return &Browser{
		allocCtx:      allocCtx,
		allocCancel:   allocCancel,
		browserCtx:    browserCtx,
		browserCancel: browserCancel,
		opts:          opts,
		remoteURL:     opts.RemoteURL,
	}, nil
}

// Available reports whether the browser's context is still live. It returns
// false once Close has run or the underlying browser process has died.
func (b *Browser) Available() bool {
	return b.browserCtx.Err() == nil
}

// Close terminates the browser process and releases the allocator. It is safe
// to call more than once; only the first call has any effect.
func (b *Browser) Close() error {
	b.closeOnce.Do(func() {
		b.browserCancel()
		b.allocCancel()
	})
	return nil
}

// newTab creates a chromedp context for a single isolated tab, bounded by both
// the caller's ctx and this Browser's configured Timeout. The returned cancel
// must be called to release the tab; it is safe to call multiple times.
func (b *Browser) newTab(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if !b.Available() {
		return nil, nil, errors.New("domexec: browser is closed")
	}
	// Remote mode dials a fresh CDP connection per tab rather than sharing this
	// Browser's warm-up connection. Measured against obscura serve: rapid
	// create/navigate/cancel cycles over ONE connection eventually lose their
	// server-side sessions ("executor for page-N-session doesn't exist"), which
	// reads downstream as zero observations — a false negative. A fresh
	// connection per check is the shape the server is built for (each gets its
	// own thread and V8 isolate, so isolation is if anything stronger), costs
	// one localhost dial, and was 20/20 stable where shared tabs were 10/20.
	if b.remoteURL != "" {
		tabAllocCtx, tabAllocCancel := chromedp.NewRemoteAllocator(ctx, b.remoteURL)
		tabCtx, tabCancel := chromedp.NewContext(tabAllocCtx)
		opCtx, opCancel := context.WithTimeout(tabCtx, b.opts.resolvedTimeout())
		stop := context.AfterFunc(ctx, func() {
			opCancel()
			tabCancel()
			tabAllocCancel()
		})
		cancel := func() {
			stop()
			opCancel()
			tabCancel()
			tabAllocCancel()
		}
		return opCtx, cancel, nil
	}
	tabCtx, tabCancel := chromedp.NewContext(b.browserCtx)
	opCtx, opCancel := context.WithTimeout(tabCtx, b.opts.resolvedTimeout())
	stop := context.AfterFunc(ctx, func() {
		opCancel()
		tabCancel()
	})
	cancel := func() {
		stop()
		opCancel()
		tabCancel()
	}
	return opCtx, cancel, nil
}
