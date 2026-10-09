package browser

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"go.uber.org/zap"
)

// The launch contract, without a browser: the profile, the proxy, the loopback bypass removed, the CA
// pinned by SPKI rather than every certificate error ignored, and the settings' switches.
func TestArgsCarryTheLaunchContract(t *testing.T) {
	ca := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("spki")}
	args := Args(Settings{AllowNoSandbox: true, DisableGPU: true}, "/p", Spec{
		ProxyAddr: "127.0.0.1:8080", CA: ca, URL: "https://t.test/", Extensions: []string{"/e1", "/e2"},
	})
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--user-data-dir=/p", "--proxy-server=http://127.0.0.1:8080", "--proxy-bypass-list=<-loopback>",
		"--ignore-certificate-errors-spki-list=" + SPKIPin(ca), "--no-sandbox", "--disable-gpu",
		"--load-extension=/e1,/e2",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args lack %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "--ignore-certificate-errors ") || strings.HasSuffix(joined, "--ignore-certificate-errors") {
		t.Error("the blanket --ignore-certificate-errors is passed; the pin must be the only certificate exception")
	}
	if args[len(args)-1] != "https://t.test/" {
		t.Errorf("the URL is not the last argument: %v", args)
	}
	if def := Args(DefaultSettings(), "/p", Spec{ProxyAddr: "a:1"}); strings.Contains(strings.Join(def, " "), "--no-sandbox") {
		t.Error("the default settings drop the sandbox")
	}
}

// A bypass host (burpsy's own web host, for the DOM auditor's hit reports) is added to the bypass
// list AFTER <-loopback>, so loopback targets are still proxied while that one host is reached
// directly (burpsy-react-ui-wl94).
func TestArgsBypassTheNamedHostButStillProxyLoopback(t *testing.T) {
	args := Args(DefaultSettings(), "/p", Spec{ProxyAddr: "127.0.0.1:8080", BypassProxyFor: []string{"127.0.0.1:8099"}})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--proxy-bypass-list=<-loopback>;127.0.0.1:8099") {
		t.Errorf("bypass list is wrong:\n%s", joined)
	}
}

// Every refusal names its cause rather than leaving a button that does nothing.
func TestLaunchRefusesByName(t *testing.T) {
	l := New(t.TempDir())
	l.resolve = func() (string, error) { return "/bin/true", nil }
	l.getenv = func(string) string { return ":0" }
	l.euid = func() int { return 1000 }

	if _, err := l.Launch(Spec{}); !errors.Is(err, ErrNoListener) {
		t.Errorf("no listener = %v, want ErrNoListener", err)
	}

	l.resolve = func() (string, error) { return "", errors.New("looked for chromium") }
	if _, err := l.Launch(Spec{ProxyAddr: "127.0.0.1:1"}); err == nil || !strings.Contains(err.Error(), "no Chromium binary") {
		t.Errorf("no binary = %v", err)
	}
	l.resolve = func() (string, error) { return "/bin/true", nil }

	if l.euid = func() int { return 0 }; true {
		if _, err := l.Launch(Spec{ProxyAddr: "127.0.0.1:1"}); err == nil || !strings.Contains(err.Error(), "root") {
			t.Errorf("root with the sandbox on = %v, want a refusal naming root", err)
		}
	}
	l.euid = func() int { return 1000 }
	l.getenv = func(string) string { return "" }
	if _, err := l.Launch(Spec{ProxyAddr: "127.0.0.1:1"}); err == nil || !strings.Contains(err.Error(), "display") {
		t.Errorf("no display = %v, want a refusal naming the display", err)
	}
}

// A relative profile directory is refused, and clearing data while the browser runs is refused.
func TestSettingsAndClearRefusals(t *testing.T) {
	l := New(t.TempDir())
	if err := l.SetSettings(Settings{DataDir: "relative/dir"}); err == nil {
		t.Error("a relative data directory was accepted")
	}
	dir := filepath.Join(t.TempDir(), "profile")
	if err := l.SetSettings(Settings{DataDir: dir, StoreData: true}); err != nil {
		t.Fatal(err)
	}
	if got, err := l.ClearData(); err != nil || got != dir {
		t.Errorf("ClearData = %q %v", got, err)
	}
}

// THE ACCEPTANCE TEST, against a real Chromium: an HTTPS page loaded in the launched browser lands in
// HTTP history — with no manual proxy setting and no CA import — and the CA pin is what makes it work:
// the same launch WITHOUT the pin never reaches the origin, because Chromium aborts at the TLS
// handshake on burpsy's certificate. Run headless (the launch path appends the flag) so the test does
// not open windows; every other argument is the operator's launch exactly.
func TestAnHTTPSPageLoadedInTheBrowserReachesHistoryWithNoCertificateWarning(t *testing.T) {
	if _, err := domexec.ResolveChromePath(""); err != nil {
		t.Skip("no Chromium on this machine: ", err)
	}

	hits := make(chan string, 16)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- r.URL.Path
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>through burpsy</body></html>"))
	}))
	defer origin.Close()

	engine, err := proxy.LoadOrGenerateCA(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	policy := proxy.NewTlsPolicy()
	policy.WithEngine(engine)
	store := core.NewTrafficStore()
	srv := proxy.NewServer(proxy.NewProxyConfig(store).
		WithScope(core.NewScope()).
		WithTlsPolicy(policy).
		WithUpstreamTLS(proxy.NewTLSPolicy().WithVerify(false)).
		WithLogger(zap.NewNop()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx, "127.0.0.1:0") }()
	proxyAddr := ""
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && proxyAddr == ""; time.Sleep(20 * time.Millisecond) {
		for _, ls := range srv.Listeners() {
			if ls.BoundAddr != "" {
				proxyAddr = ls.BoundAddr
			}
		}
	}
	if proxyAddr == "" {
		t.Fatal("the proxy never bound")
	}
	ca, _, _ := engine.ExportCA()

	// launch returns the launcher so the caller can tell when this browser has exited. Each launch
	// gets its own launcher and its own profile, so one browser's exit says nothing about another's.
	launch := func(path string, pin bool) *Launcher {
		t.Helper()
		l := New(t.TempDir())
		// Fresh profile per launch, and no sandbox because CI runs as root.
		_ = l.SetSettings(Settings{StoreData: false, AllowNoSandbox: true})
		spec := Spec{ProxyAddr: proxyAddr, URL: origin.URL + path,
			extraArgs: []string{"--headless=new", "--dump-dom", "--disable-gpu"}}
		if pin {
			spec.CA = ca
		}
		if _, err := l.Launch(spec); err != nil {
			t.Fatalf("Launch: %v", err)
		}
		return l
	}
	// awaitHit waits for the origin to see path, or for the browser to exit, or for the deadline,
	// and reports which. --dump-dom makes Chromium exit once the page (or its certificate error)
	// has finished loading, so the exit is the event that settles the question: a browser that
	// has exited can request nothing more. A request already in flight through the proxy when it
	// exits is still given exitGrace to land, so an exit can never cut a hit short.
	//
	// Running() is false both after the process exits and when it exited inside Launch's startup
	// window (a fast --dump-dom), which Launch reports as a hand-off and never registers.
	const exitGrace = time.Second
	awaitHit := func(l *Launcher, path string, within time.Duration) (hit, exited bool) {
		deadline := time.After(within)
		poll := time.NewTicker(20 * time.Millisecond)
		defer poll.Stop()
		var grace <-chan time.Time
		for {
			select {
			case p := <-hits:
				if p == path {
					return true, false
				}
			case <-poll.C:
				if grace == nil && !l.Running() {
					grace = time.After(exitGrace)
				}
			case <-grace:
				return false, true
			case <-deadline:
				return false, false
			}
		}
	}

	// Negative control first: without the pin, Chromium refuses burpsy's certificate and the request
	// never reaches the origin. This used to wait out a fixed 8s on every run; it now ends when the
	// browser does, and the 8s stays as the cap for a browser that never exits.
	unpinned := launch("/unpinned", false)
	if hit, _ := awaitHit(unpinned, "/unpinned", 8*time.Second); hit {
		t.Fatal("the origin was reached WITHOUT the CA pin — the test cannot tell the pin from a browser " +
			"that ignores certificate errors")
	}

	// The pinned load ends either at the hit or at the browser's exit. A browser that exited
	// without the origin seeing the request is a definite failure and is reported at once; one
	// still loading on a slow runner is given until the cap. The old fixed 20s was the cap AND the
	// only signal, so a loaded runner's slow Chromium start read as "the pin does not work".
	pinned := launch("/pinned", true)
	hit, exited := awaitHit(pinned, "/pinned", 60*time.Second)
	if !hit {
		if exited {
			t.Fatal("the pinned browser loaded and exited without the origin ever seeing /pinned: the " +
				"page did not load through burpsy")
		}
		t.Fatal("the pinned launch never reached the origin within 60s and the browser never finished " +
			"loading: the page did not load through burpsy")
	}
	var found bool
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && !found; time.Sleep(50 * time.Millisecond) {
		for _, ex := range store.Exchanges() {
			if ex != nil && ex.Path == "/pinned" && ex.TLS {
				found = true
			}
		}
	}
	if !found {
		t.Error("the page loaded but no HTTPS exchange for /pinned is in history")
	}
}
