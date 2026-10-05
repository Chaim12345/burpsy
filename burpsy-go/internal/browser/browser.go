// Package browser launches the operator's pre-wired Chromium (burpsy-react-ui-bufa): Burp's
// "Open browser" — a Chromium on its own profile, pointed at a live proxy listener, trusting burpsy's
// CA for that one profile, so every page loaded in it reaches HTTP history without the operator
// configuring a proxy or importing a CA into a machine-wide trust store.
//
// # Why this is not internal/domexec
//
// domexec drives the scanner's headless DOM harness, and it must stay headless, extension-free and
// unproxied: its answers are evidence about a page, and a profile an operator has browsed with (or an
// extension loaded into it) would contaminate them. This package shares exactly one thing with it —
// how a Chromium binary is found (domexec.ResolveChromePath) — and nothing else.
//
// # How the certificate warning is avoided without a CA import
//
// --ignore-certificate-errors-spki-list pins burpsy's own CA by the SHA-256 of its public key, for
// this profile only. That is narrower than Burp's blanket --ignore-certificate-errors: a certificate
// that is neither burpsy's CA nor validly chained still warns, so a profile used to browse cannot
// silently accept an attacker's certificate. The pin matches because the MITM presents the CA in every
// leaf chain (internal/proxy: Certificate: [leaf, ca]).
package browser

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/domexec"
)

// Settings is the browser's configuration, under Burp's key names: browser_data_directory and
// allow_saving_browser_settings (user_options.misc.embedded_browser, Zblz.java:2656-2658) and
// allow_running_without_sandbox and disable_gpu (project_options.misc.embedded_browser, :2776-2777).
type Settings struct {
	// DataDir is the profile directory. Empty means the launcher's per-project default.
	DataDir string `json:"browser_data_directory"`
	// StoreData keeps the profile between launches (cookies, logins, history). Off means every launch
	// gets a fresh temporary profile that is deleted when the browser exits.
	StoreData bool `json:"allow_saving_browser_settings"`
	// AllowNoSandbox runs Chromium with --no-sandbox, which Chromium REQUIRES when the process runs as
	// root. Off by default: the sandbox is the browser's main defence against the pages it renders,
	// and an operator browsing a target is exactly the case it exists for.
	AllowNoSandbox bool `json:"allow_running_without_sandbox"`
	// DisableGPU passes --disable-gpu, for hosts whose GPU stack makes Chromium crash or render blank.
	DisableGPU bool `json:"disable_gpu"`
}

// DefaultSettings is Burp's default: keep the profile, keep the sandbox, keep the GPU.
func DefaultSettings() Settings { return Settings{StoreData: true} }

// Spec is one launch.
type Spec struct {
	// ProxyAddr is the host:port of the live proxy listener the browser routes through.
	ProxyAddr string
	// CA is burpsy's signing certificate, pinned for this profile. Nil when TLS interception is off:
	// HTTPS then passes through the proxy as an opaque tunnel and needs no pin.
	CA *x509.Certificate
	// URL is the page to open; empty opens a blank tab.
	URL string
	// Extensions are unpacked extension directories for --load-extension. A list so a DOM-Invader-style
	// extension can join later without changing the launch path.
	Extensions []string
	// BypassProxyFor are host:port patterns the browser reaches directly rather than through the
	// proxy. burpsy's own web host goes here when the DOM auditor is loaded (burpsy-react-ui-wl94), so
	// the extension's hit reports are a direct loopback POST rather than traffic through — and
	// recorded by — the very proxy they describe. Everything else, loopback targets included, still
	// goes through the proxy (see the <-loopback> note in Args).
	BypassProxyFor []string
	// extraArgs are appended verbatim — tests use them to run the same launch headless.
	extraArgs []string
}

// Result is what a launch reports.
type Result struct {
	PID        int    `json:"pid,omitempty"`
	ProfileDir string `json:"profile_dir"`
	Proxy      string `json:"proxy"`
	// PinnedCA is the SPKI pin the profile trusts, empty when interception is off.
	PinnedCA string `json:"pinned_ca,omitempty"`
	// HandedOff is true when a browser was already running on this profile: Chromium hands the URL to
	// that instance (a new tab) and the launched process exits at once, which is success, not a crash.
	HandedOff bool   `json:"handed_off,omitempty"`
	Binary    string `json:"binary"`
}

// ErrNoListener is Burp's own refusal (Zpk5.java:797-806), worded the same.
var ErrNoListener = errors.New("unable to start burpsy's browser - no Proxy listeners available; add or enable a listener in Proxy settings")

// Launcher owns the browser process and its settings.
type Launcher struct {
	mu         sync.Mutex
	settings   Settings
	defaultDir string
	running    *exec.Cmd
	tempDir    string

	// Seams for tests and for the honest refusals: how the binary is found, what the environment says,
	// and who the process runs as.
	resolve func() (string, error)
	getenv  func(string) string
	euid    func() int
}

// New returns a launcher whose default profile directory is defaultDir.
func New(defaultDir string) *Launcher {
	return &Launcher{
		settings:   DefaultSettings(),
		defaultDir: defaultDir,
		resolve:    func() (string, error) { return domexec.ResolveChromePath("") },
		getenv:     os.Getenv,
		euid:       os.Geteuid,
	}
}

// Settings returns the current settings.
func (l *Launcher) Settings() Settings {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.settings
}

// SetSettings replaces them. A relative data directory is refused: it would resolve against whatever
// the backend's working directory happens to be, and a profile full of an engagement's cookies must
// live where the operator said.
func (l *Launcher) SetSettings(s Settings) error {
	if s.DataDir != "" && !filepath.IsAbs(s.DataDir) {
		return fmt.Errorf("browser_data_directory %q must be an absolute path", s.DataDir)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.settings = s
	return nil
}

// SetDefaultDir changes the per-project default profile directory, e.g. after a project switch.
func (l *Launcher) SetDefaultDir(dir string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.defaultDir = dir
}

// ProfileDir is the profile a stored-data launch uses.
func (l *Launcher) ProfileDir() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.profileDirLocked()
}

func (l *Launcher) profileDirLocked() string {
	if l.settings.DataDir != "" {
		return l.settings.DataDir
	}
	return l.defaultDir
}

// Running reports whether a browser this launcher started is still running.
func (l *Launcher) Running() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.running != nil
}

// SPKIPin is the --ignore-certificate-errors-spki-list value for a certificate: base64 of the SHA-256
// of its SubjectPublicKeyInfo.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// bypassList renders Chromium's --proxy-bypass-list: the <-loopback> token first (undo the implicit
// loopback bypass, so a target on localhost is still proxied), then any explicit host:port burpsy
// wants reached directly. Order matters — <-loopback> subtracts, the explicit entries add back only
// the one or two hosts named.
func bypassList(extra []string) string {
	parts := append([]string{"<-loopback>"}, extra...)
	return strings.Join(parts, ";")
}

// Args builds Chromium's command line. Pure, so the launch contract is testable without a browser.
func Args(set Settings, profileDir string, spec Spec) []string {
	args := []string{
		"--user-data-dir=" + profileDir,
		"--proxy-server=http://" + spec.ProxyAddr,
		// Chromium bypasses the proxy for loopback by default; a target on localhost is still a target,
		// and its traffic belongs in history like any other.
		"--proxy-bypass-list=" + bypassList(spec.BypassProxyFor),
		"--no-first-run",
		"--no-default-browser-check",
		"--class=burpsy-browser",
	}
	if spec.CA != nil {
		args = append(args, "--ignore-certificate-errors-spki-list="+SPKIPin(spec.CA))
	}
	if set.AllowNoSandbox {
		args = append(args, "--no-sandbox")
	}
	if set.DisableGPU {
		args = append(args, "--disable-gpu")
	}
	if len(spec.Extensions) > 0 {
		args = append(args, "--load-extension="+strings.Join(spec.Extensions, ","))
	}
	args = append(args, spec.extraArgs...)
	url := spec.URL
	if url == "" {
		url = "about:blank"
	}
	return append(args, url)
}

// startupWindow is how long a launch watches the process for an immediate exit. Chromium that fails
// to start (no display, sandbox refused as root, bad profile) exits within this window; one that
// started keeps running.
const startupWindow = 1500 * time.Millisecond

// Launch starts the browser, or hands the URL to the one already running on this profile. Every
// refusal names its cause — no listener, no binary, root without the sandbox setting, no display —
// following domexec's honest-failure contract: a browser that silently fails to appear reads as the
// button being broken.
func (l *Launcher) Launch(spec Spec) (Result, error) {
	if strings.TrimSpace(spec.ProxyAddr) == "" {
		return Result{}, ErrNoListener
	}
	bin, err := l.resolve()
	if err != nil {
		return Result{}, fmt.Errorf("no Chromium binary to launch: %w", err)
	}
	set := l.Settings()
	headless := false
	for _, a := range spec.extraArgs {
		headless = headless || strings.HasPrefix(a, "--headless")
	}
	if runtime.GOOS == "linux" && l.euid() == 0 && !set.AllowNoSandbox {
		return Result{}, errors.New("burpsy is running as root, and Chromium refuses to start as root with its " +
			"sandbox on; either run burpsy as a non-root user, or enable 'allow_running_without_sandbox' in " +
			"the browser settings (the sandbox is the browser's defence against the pages it renders)")
	}
	if runtime.GOOS == "linux" && !headless && l.getenv("DISPLAY") == "" && l.getenv("WAYLAND_DISPLAY") == "" {
		return Result{}, errors.New("there is no display for the browser window (neither DISPLAY nor " +
			"WAYLAND_DISPLAY is set where burpsy's backend runs); the browser opens on the machine running " +
			"burpsy, so start burpsy from a desktop session")
	}

	l.mu.Lock()
	profile := l.profileDirLocked()
	tempDir := ""
	if !set.StoreData && l.running == nil {
		tempDir, err = os.MkdirTemp("", "burpsy-browser-")
		if err != nil {
			l.mu.Unlock()
			return Result{}, fmt.Errorf("creating a temporary browser profile: %w", err)
		}
		profile = tempDir
	} else if !set.StoreData && l.tempDir != "" {
		// A fresh-profile browser is already running: hand the URL to it rather than starting a second
		// temporary profile.
		profile = l.tempDir
	}
	l.mu.Unlock()
	if profile == "" {
		return Result{}, errors.New("no browser profile directory is configured")
	}
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return Result{}, fmt.Errorf("creating the browser profile %s: %w", profile, err)
	}

	cmd := exec.Command(bin, Args(set, profile, spec)...)
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{w: &stderr, n: 16 * 1024}
	if err := cmd.Start(); err != nil {
		cleanupTemp(tempDir)
		return Result{}, fmt.Errorf("starting %s: %w", bin, err)
	}
	res := Result{PID: cmd.Process.Pid, ProfileDir: profile, Proxy: spec.ProxyAddr, Binary: bin}
	if spec.CA != nil {
		res.PinnedCA = SPKIPin(spec.CA)
	}

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		cleanupTemp(tempDir)
		if err == nil {
			// Exit 0 inside the window: Chromium found a browser already running on this profile and
			// gave it the URL. That is the "open URL in the running browser" path, not a failure.
			res.PID = 0
			res.HandedOff = true
			return res, nil
		}
		return Result{}, fmt.Errorf("Chromium exited at once (%v): %s", err, lastLines(stderr.String(), 6))
	case <-time.After(startupWindow):
	}

	l.mu.Lock()
	l.running = cmd
	l.tempDir = tempDir
	l.mu.Unlock()
	go func() {
		<-exited
		l.mu.Lock()
		if l.running == cmd {
			l.running = nil
			l.tempDir = ""
		}
		l.mu.Unlock()
		cleanupTemp(tempDir)
	}()
	return res, nil
}

// ClearData deletes the stored profile. Refused while the browser is running on it: Chromium holds
// the profile open, and deleting under it corrupts the profile rather than clearing it.
func (l *Launcher) ClearData() (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.running != nil {
		return "", errors.New("the browser is running; close it before clearing its data")
	}
	dir := l.profileDirLocked()
	if dir == "" {
		return "", errors.New("no browser profile directory is configured")
	}
	if err := os.RemoveAll(dir); err != nil {
		return dir, fmt.Errorf("clearing %s: %w", dir, err)
	}
	return dir, nil
}

func cleanupTemp(dir string) {
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.Join(lines, " | ")
	if out == "" {
		return "no output"
	}
	return out
}

// limitedWriter keeps at most n bytes, so a chatty browser cannot grow memory without bound.
type limitedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
	n  int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if room := lw.n - lw.w.Len(); room > 0 {
		if len(p) > room {
			lw.w.Write(p[:room])
		} else {
			lw.w.Write(p)
		}
	}
	return len(p), nil
}
