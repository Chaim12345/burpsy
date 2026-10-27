package main

// cmd/desktop is the Wails v2 desktop shell. It deliberately duplicates the
// subset of cmd/burpsy/main.go's wiring it needs (store, scope, proxy, web
// server) rather than sharing it, because cmd/burpsy owns the CLI dispatcher
// and flag surface (see cmd/AGENTS.md) and a shared wiring package is a
// larger refactor than this shell needs. The ActiveScanner is the exception:
// both entry points build it from scanner.CapabilityWiring
// (internal/scanner/wiring.go), so no binary can quietly run an audit engine
// with fewer capability handles than another. The remaining duplication is
// bounded and documented here and in docs/DESKTOP.md; behaviour changes to
// the proxy or web wiring must be mirrored in both entry points until that
// refactor lands.
//
// Hybrid mode: the desktop window never renders its own copy of the UI. It
// starts the exact same web.Server the CLI does (embedded React UI via
// go:embed in internal/web/ui.go) bound to 127.0.0.1, then points the Wails
// AssetServer at it through a reverse proxy. That keeps exactly one UI build
// and one API implementation for both the desktop window and any browser an
// operator points at the same port.
import (
	"context"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"github.com/burpsy-go/burpsy/internal/web"
	"go.uber.org/zap"
)

// App holds the Wails desktop application context and the in-process burpsy engines.
type App struct {
	ctx       context.Context
	proxyBind string
	webBind   string
	dbFile    string
	// closeProject closes the open -db project on shutdown.
	closeProject func()

	logger *zap.Logger
	store  *core.TrafficStore
	scope  *core.Scope
	cancel context.CancelFunc
}

func NewApp(proxyBind, webBind, dbFile string) *App {
	return &App{proxyBind: proxyBind, webBind: webBind, dbFile: dbFile}
}

// startup wires the same engines cmd/burpsy/main.go does — one TrafficStore, one
// Scope, one FindingStore, handed to both the proxy and the web server — then
// starts both listeners in the background. Wails calls this once the native
// window exists, so `a.ctx` is safe to use in every bound method from here on.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("desktop logger: %v", err)
	}
	a.logger = logger

	runCtx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel

	a.store = core.NewTrafficStore()
	a.scope = core.NewScope()
	findingStore := core.NewFindingStore()
	interceptEngine := intercept.NewEngine()
	passiveScanner := scanner.NewPassiveScanner(a.store, logger)

	// -db, as in cmd/burpsy: restore history, findings and scope, then mirror every write.
	var persistStore *persist.Store
	if a.dbFile != "" {
		persistStore, err = persist.Open(a.dbFile, logger)
		if err != nil {
			logger.Fatal("open project database", zap.String("db", a.dbFile), zap.Error(err))
		}
		if err := persistStore.Restore(a.store, findingStore, a.scope, nil, nil, nil, nil); err != nil {
			logger.Fatal("restore project", zap.Error(err))
		}
		web.InstallCaptureSinks(a.store, findingStore, persistStore)
	}

	// One log for the listener and the console, created before either is built: the relay
	// goroutines read it as soon as the proxy serves (burpsy-react-ui-6dt).
	toolLog := toollog.New()

	proxyConfig := proxy.NewProxyConfig(a.store).
		WithScope(a.scope).
		WithTlsPolicy(proxy.NewTlsPolicy()).
		WithLogger(logger).
		WithScanner(passiveScanner).
		WithFindings(findingStore).
		WithIntercept(interceptEngine).
		// Proxied browser traffic joins the same unified log the other tools write to.
		WithToolLog(toolLog)
	proxyServer := proxy.NewServer(proxyConfig)
	go func() {
		if err := proxyServer.ListenAndServe(runCtx, a.proxyBind); err != nil && err != context.Canceled {
			logger.Error("desktop proxy exited", zap.Error(err))
		}
	}()

	// One session coordinator for every surface that compares or edits session state — the
	// same single-handle rule cmd/burpsy/main.go follows: the console's Session page and the
	// scanner's access-control and CSRF comparisons must govern and be governed by one rule
	// set. The desktop binary previously wired no coordinator into its scanner at all, which
	// is why every session-dependent check refused here while passing in the CLI.
	sessionCoord := session.NewCoordinator(logger)
	// The corpus compiled into the binary. Desktop has no -bchecks flag, so this is always the
	// embedded set — attaching it switches check_corpus on, exactly as in the CLI
	// (WithBundledCorpus). A failure is a build defect and refuses to start, as cmd/burpsy does.
	bundledChecks, berr := scanner.BundledCorpus(logger)
	if berr != nil {
		logger.Fatal("bundled bcheck corpus", zap.Error(berr))
	}
	// One construction recipe for every binary — internal/scanner/wiring.go. Desktop wires the
	// same capability handles the CLI does (ledgers, session coordinator, JS-library and JWT
	// checks, bundled corpus); the handles it has no source for (OOB server, tool allowlist,
	// DOM engine, audit-config flags) stay nil as explicit opt-outs, and the checks that need
	// them keep reporting the missing capability by name.
	caps := scanner.CapabilityWiring{
		SessionCoordinator: sessionCoord,
		CorpusChecks:       passiveScanner.ActiveChecks(),
		BundledCorpus:      bundledChecks,
	}
	webServer := web.NewServer(a.store, a.scope).
		// First in the chain, so a later WithPersist restores into and mirrors the same
		// instance the proxy records into.
		WithToolLog(toolLog).
		WithLogger(logger).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithScanner(scanner.NewActiveScanner(a.store, logger).
			WithSender(sender.NewSender(sender.DefaultSenderConfig())).
			WithScope(a.scope).
			WithCapabilities(caps)).
		// The same recipe, handed to the lazy fallback so a scanner built on first audit
		// wires the same handles this one did (internal/web/api_scanner_audit.go).
		WithScannerCapabilities(caps).
		// The same coordinator the scanner holds, so the Session page's rules and the
		// scanner's session-dependent checks are one rule set — the wiring cmd/burpsy
		// already had and this binary lacked.
		WithSessionCoordinator(sessionCoord).
		WithPassiveScanner(passiveScanner).
		WithFindings(findingStore).
		WithIntercept(interceptEngine).
		WithBindAddrs(a.proxyBind, a.webBind)
	if persistStore != nil {
		webServer.WithPersist(persistStore)
		a.closeProject = webServer.CloseProject
	}
	webServer.StartLiveAuditSweep(runCtx)
	go func() {
		if err := webServer.ListenAndServe(runCtx, a.webBind); err != nil && err != context.Canceled {
			logger.Error("desktop web server exited", zap.Error(err))
		}
	}()
}

// shutdown cancels the running proxy/web listeners and seals the capture's
// tail — the same Sync-not-Close discipline cmd/burpsy/main.go uses, so
// handlers still unwinding keep their mapped spans valid.
func (a *App) shutdown(ctx context.Context) {
	if a.cancel != nil {
		a.cancel()
	}
	if a.store != nil {
		if err := a.store.Sync(); err != nil && a.logger != nil {
			a.logger.Error("failed to seal capture on shutdown", zap.Error(err))
		}
	}
	if a.closeProject != nil {
		a.closeProject()
	}
}

// SaveFileDialog opens a native OS save dialog. Bound so the React UI can call
// it in desktop mode instead of the browser's forced-download fallback.
func (a *App) SaveFileDialog(title, defaultFilename string) (string, error) {
	return runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{Title: title, DefaultFilename: defaultFilename})
}

// OpenFileDialog opens a native OS open dialog.
func (a *App) OpenFileDialog(title string) (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{Title: title})
}

// Notify raises a frontend event the React shell can render as a toast. Wails
// v2's classic runtime does not ship a cross-platform native-notification API
// on Linux without extra per-OS wiring, so this stays a same-process event
// rather than a half-working native notification — see docs/DESKTOP.md.
func (a *App) Notify(title, message string) {
	runtime.EventsEmit(a.ctx, "burpsy:notify", map[string]string{"title": title, "message": message})
}

// RuntimeMode tells the frontend it is running inside the desktop shell —
// src/lib/runtime.ts checks window.go/window.runtime instead of calling this,
// but it stays available as a direct binding for parity with the plan doc.
func (a *App) RuntimeMode() string { return "desktop" }

func buildMenu(app *App) *menu.Menu {
	m := menu.NewMenu()

	fileMenu := m.AddSubmenu("File")
	fileMenu.AddText("Export History...", keys.CmdOrCtrl("e"), func(_ *menu.CallbackData) {
		runtime.EventsEmit(app.ctx, "burpsy:menu", "export-history")
	})
	fileMenu.AddSeparator()
	fileMenu.AddText("Quit", keys.CmdOrCtrl("q"), func(_ *menu.CallbackData) {
		runtime.Quit(app.ctx)
	})

	viewMenu := m.AddSubmenu("View")
	viewMenu.AddText("Toggle Theme", keys.Combo("l", keys.CmdOrCtrlKey, keys.ShiftKey), func(_ *menu.CallbackData) {
		runtime.EventsEmit(app.ctx, "burpsy:menu", "toggle-theme")
	})
	viewMenu.AddText("Command Palette", keys.CmdOrCtrl("k"), func(_ *menu.CallbackData) {
		runtime.EventsEmit(app.ctx, "burpsy:menu", "command-palette")
	})

	// Every Burp tool that carries an alt+N hotkey in the web shell (nav.ts), in
	// nav order, so the menu accelerators match the in-app ones exactly. The
	// event is handled by src/app.tsx's desktop menu bridge, the same handler
	// the hotkeys drive — a menu click and a keyboard shortcut are one code path.
	toolsMenu := m.AddSubmenu("Tools")
	for _, item := range []struct {
		label string
		route string
		key   string
	}{
		{"Target", "sitemap", "2"},
		{"Proxy", "intercept", "3"},
		{"Intruder", "intruder", "4"},
		{"Repeater", "repeater", "5"},
		{"Sequencer", "sequencer", "6"},
		{"Decoder", "decoder", "7"},
		{"Comparer", "comparer", "8"},
		{"Logger", "logger", "9"},
		{"Organizer", "organizer", "0"},
	} {
		route := item.route
		toolsMenu.AddText(item.label, keys.OptionOrAlt(item.key), func(_ *menu.CallbackData) {
			runtime.EventsEmit(app.ctx, "burpsy:navigate", route)
		})
	}

	helpMenu := m.AddSubmenu("Help")
	helpMenu.AddText("Keyboard Shortcuts", keys.Key("?"), func(_ *menu.CallbackData) {
		runtime.EventsEmit(app.ctx, "burpsy:menu", "shortcuts")
	})

	return m
}

func main() {
	proxyBind := flag.String("proxy", "127.0.0.1:8080", "proxy bind address")
	webBind := flag.String("web", "127.0.0.1:8081", "web UI bind address (also what the desktop window loads, and what a remote browser can reach — hybrid mode)")
	dbFile := flag.String("db", "", "SQLite database for persistent state (history, findings, scope, rules)")
	flag.Parse()

	app := NewApp(*proxyBind, *webBind, *dbFile)

	target, err := url.Parse("http://" + *webBind)
	if err != nil {
		log.Fatalf("invalid -web address %q: %v", *webBind, err)
	}
	// The webview's AssetServer.Handler reverse-proxies every request to the
	// in-process web.Server started in startup(), so the desktop window and a
	// remote browser at the same address render byte-identical UI and hit the
	// same API — one build, one server, two ways to reach it.
	// The webview's own requests arrive with the asset server's Host (wails / wails.localhost), and
	// the console refuses any Host it was not bound to on EVERY method, reads included
	// (burpsy-react-ui-rebind-read). This handler only ever carries the in-process webview's
	// requests, so it forwards them as what they are: requests for the bound console.
	proxyHandler := &httputil.ReverseProxy{Rewrite: consoleRewrite(target)}

	err = wails.Run(&options.App{
		Title:  "burpsy",
		Width:  1400,
		Height: 900,
		AssetServer: &assetserver.Options{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxyHandler.ServeHTTP(w, r)
			}),
		},
		Menu:       buildMenu(app),
		OnStartup:  app.startup,
		OnShutdown: app.shutdown,
		Bind:       []interface{}{app},
	})
	if err != nil {
		log.Fatal(err)
	}
}

// webviewOrigins are the origins the wails webview's own pages send: wails:// on macOS/Linux,
// http(s)://wails.localhost on Windows (WebView2).
var webviewOrigins = map[string]bool{
	"wails://wails":           true,
	"wails://wails.localhost": true,
	"http://wails.localhost":  true,
	"https://wails.localhost": true,
}

// consoleRewrite forwards the webview's requests as requests for the bound console. The console
// refuses any Host it was not bound to on every method (burpsy-react-ui-rebind-read), and on a
// POST/PUT/PATCH/DELETE it also refuses an Origin that does not match the Host — which the webview's
// own origin never does, so every write from the desktop window was refused
// (burpsy-react-ui-desktop-origin). Only the webview's known origins are rewritten: anything else
// is passed through for the console to judge, so this handler never launders a foreign origin.
func consoleRewrite(target *url.URL) func(*httputil.ProxyRequest) {
	return func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		pr.Out.Host = target.Host
		if webviewOrigins[pr.In.Header.Get("Origin")] {
			pr.Out.Header.Set("Origin", "http://"+target.Host)
		}
	}
}
