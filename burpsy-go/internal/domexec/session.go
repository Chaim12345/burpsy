package domexec

// Isolated, scope-gated browser sessions (burpsy-react-ui-xhtk).
//
// # Why a session and not a tab
//
// Every tab newTab makes is a child of the Browser's one default browser context, which the
// scanner's DOM checks share. A recorded login replayed there would leave its session cookies in the
// jar every later taint observation loads pages with — evidence gathered logged-in that was meant to
// be gathered logged-out — and two crawls with two logins would overwrite each other. A Session is a
// CDP browser context of its own (Target.createBrowserContext): its own cookie jar and storage,
// disposed when the session closes. Tabs opened from it share that jar, which is what lets an
// authenticated crawl's render pass see the logged-in application.
//
// # The scope gate
//
// The browser had no scope gate: a render navigates to a URL the crawler already authorised, and the
// page then loads whatever it likes. For a LOGIN that is not acceptable — a replay clicks, follows
// redirects and submits forms on its own — so a gated session enforces scope twice:
//
//   - A per-context proxy (Target.createBrowserContext's proxyServer) on loopback that refuses any
//     request whose authority scope cannot contain. It covers every target in the context — the page,
//     cross-site iframes running out of process, popups, workers — because they all share the
//     context's network stack. For HTTPS it sees only CONNECT host:port, so it is an authority check.
//   - Fetch interception in each tab a session opens, which pauses every request the page makes,
//     redirect hops included, and checks the FULL URL — path included — before continuing it.
//
// Every refusal is recorded (Blocked) so a replay that failed because the identity provider is not in
// scope says so rather than reading as a broken login. This is a deliberate difference from Burp,
// which lets a recorded login "temporarily follow any out-of-scope links that are necessary to perform
// the login sequence" (recorded-login-sequences.html): here scope is enforced on the request actually
// sent, so an SSO identity provider must be added to scope. See gaps.md, Crawler B.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/security"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

// ScopeGate decides whether the session's browser may send a request.
type ScopeGate interface {
	// AllowURL is asked for every request whose full URL is visible (Fetch interception, plain HTTP
	// through the proxy). nil means allowed; an error is the reason it is not.
	AllowURL(u *url.URL) error
	// AllowAuthority is asked for an HTTPS tunnel, where only host and port are visible.
	AllowAuthority(host string, port uint16, tls bool) error
}

// Session is one isolated browser context.
type Session struct {
	b     *Browser
	id    cdp.BrowserContextID
	gate  ScopeGate
	proxy *gateProxy

	mu      sync.Mutex
	closed  bool
	blocked []string
	// renderBlocked are the refusals made while no replay was running — the render pass's pages, in an
	// authenticated crawl — kept apart so a replay's own list does not swallow them (and so a page whose
	// script lives on an out-of-scope CDN is reported, not silently empty).
	renderBlocked []string
	replaying     bool
	// ignoreCertErrors follows the operator's TLS verification setting; see IgnoreCertificateErrors.
	ignoreCertErrors bool
}

// IgnoreCertificateErrors makes the session's tabs accept a certificate the browser cannot verify. It
// exists for one reason: the operator turned TLS verification off for every leg (Settings → Network),
// as an assessor does for a self-signed or internal-CA staging host, and a recorded login that refused
// the certificate every other request accepts would fail on step 1 for a reason nobody chose. It is
// applied per TAB (Security.setIgnoreCertificateErrors on the tab's own session), so the shared
// browser's other tabs — the DOM checks — keep verifying; TestIgnoringCertificateErrorsIsScopedToTheSession
// pins that. Call before opening tabs.
func (s *Session) IgnoreCertificateErrors(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ignoreCertErrors = on
}

// MaxBlockedRecorded bounds the refusal list one session keeps.
const MaxBlockedRecorded = 100

// NewSession opens an isolated browser context. A nil gate is an ungated session; every caller in
// this tree passes one.
//
// Remote engines (obscura, lightpanda) are refused: this build has only verified browser contexts and
// per-context proxies against Chrome, and a remote server that silently ignored either would hand the
// login the shared jar or an ungated network — the two things a session exists to prevent.
//
// The context and its tabs are made with raw Target commands rather than chromedp's
// WithNewBrowserContext, and that is measured, not stylistic: against this build's Chromium (147,
// headless) Target.createTarget into a new browser context fails with "Failed to open new tab - no
// browser is open" unless newWindow is set, and chromedp never sets it. Every tab here is created with
// newWindow and then attached with chromedp.WithTargetID.
func (b *Browser) NewSession(gate ScopeGate) (*Session, error) {
	if b.remoteURL != "" {
		return nil, errors.New("domexec: isolated sessions (recorded logins) need a local Chrome; the remote CDP engine at " +
			b.remoteURL + " is not supported for them")
	}
	if !b.Available() {
		return nil, errors.New("domexec: browser is closed")
	}
	s := &Session{b: b, gate: gate}
	params := target.CreateBrowserContext().WithDisposeOnDetach(true)
	if gate != nil {
		p, err := startGateProxy(gate, s.recordBlocked)
		if err != nil {
			return nil, err
		}
		s.proxy = p
		// "<-loopback>" removes Chrome's implicit loopback bypass, so a target on 127.0.0.1 is gated
		// like any other — the same subtraction internal/browser makes for the operator's browser.
		params = params.WithProxyServer("http://" + p.addr()).WithProxyBypassList("<-loopback>")
	}
	ctx, cancel := context.WithTimeout(b.browserCtx, b.opts.resolvedTimeout())
	defer cancel()
	ex, err := b.browserExecutor(ctx)
	if err != nil {
		s.closeProxy()
		return nil, err
	}
	id, err := params.Do(ex)
	if err != nil {
		s.closeProxy()
		return nil, fmt.Errorf("domexec: could not open an isolated browser context: %w", err)
	}
	s.id = id
	return s, nil
}

// browserExecutor is the browser-level CDP connection, for Target and Storage commands.
func (b *Browser) browserExecutor(ctx context.Context) (context.Context, error) {
	c := chromedp.FromContext(b.browserCtx)
	if c == nil || c.Browser == nil {
		return nil, errors.New("domexec: the browser has no CDP connection")
	}
	return cdp.WithExecutor(ctx, c.Browser), nil
}

// Close disposes the browser context — its cookies, storage and tabs — and stops the proxy.
func (s *Session) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	already := s.closed
	s.closed = true
	s.mu.Unlock()
	if already {
		return
	}
	if s.id != "" && s.b.Available() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if ex, err := s.b.browserExecutor(ctx); err == nil {
			_ = target.DisposeBrowserContext(s.id).Do(ex)
		}
		cancel()
	}
	s.closeProxy()
}

func (s *Session) closeProxy() {
	if s.proxy != nil {
		s.proxy.close()
	}
}

// Available reports whether the session's context is still open.
func (s *Session) Available() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.b.Available()
}

// Blocked returns the requests the gate refused, oldest first.
func (s *Session) Blocked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.blocked...)
}

// TakeBlocked returns and clears the refusal list, so one replay reports only its own.
func (s *Session) TakeBlocked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]string{}, s.blocked...)
	s.blocked = nil
	return out
}

func (s *Session) recordBlocked(what string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := &s.blocked
	if !s.replaying {
		list = &s.renderBlocked
	}
	for _, b := range *list {
		if b == what {
			return
		}
	}
	if len(*list) < MaxBlockedRecorded {
		*list = append(*list, what)
	}
}

// RenderBlocked returns the refusals made outside any replay — by the authenticated render pass.
func (s *Session) RenderBlocked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.renderBlocked...)
}

func (s *Session) setReplaying(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replaying = on
}

// newTab opens a tab in this session's browser context, gated by Fetch interception, bounded by
// timeout.
func (s *Session) newTab(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc, error) {
	if !s.Available() {
		return nil, nil, errors.New("domexec: the browser session is closed")
	}
	createCtx, createCancel := context.WithTimeout(ctx, s.b.opts.resolvedTimeout())
	ex, err := s.b.browserExecutor(createCtx)
	if err != nil {
		createCancel()
		return nil, nil, err
	}
	tid, err := target.CreateTarget("about:blank").WithBrowserContextID(s.id).WithNewWindow(true).Do(ex)
	createCancel()
	if err != nil {
		return nil, nil, fmt.Errorf("domexec: could not open a tab in the session: %w", err)
	}
	// Attached under the Browser's context so cancelling the tab closes only the tab; the browser
	// context itself is disposed by Close.
	tabCtx, tabCancel := chromedp.NewContext(s.b.browserCtx, chromedp.WithTargetID(tid))
	opCtx, opCancel := context.WithTimeout(tabCtx, timeout)
	stop := context.AfterFunc(ctx, func() { opCancel(); tabCancel() })
	cancel := func() {
		stop()
		opCancel()
		closeTargetByID(s.b.browserCtx, tid)
		tabCancel()
	}
	if err := chromedp.Run(opCtx); err != nil {
		cancel()
		return nil, nil, fmt.Errorf("domexec: could not attach to the session's tab: %w", err)
	}
	s.mu.Lock()
	ignore := s.ignoreCertErrors
	s.mu.Unlock()
	if ignore {
		if err := chromedp.Run(opCtx, security.SetIgnoreCertificateErrors(true)); err != nil {
			cancel()
			return nil, nil, fmt.Errorf("domexec: could not relax certificate checks in the session's tab: %w", err)
		}
	}
	if s.gate != nil {
		if err := s.installFetchGate(opCtx); err != nil {
			cancel()
			return nil, nil, err
		}
	}
	return opCtx, cancel, nil
}

// installFetchGate pauses every request the tab makes at the request stage and continues only the
// ones the gate allows. The decision runs in its own goroutine because a CDP command issued from
// inside a ListenTarget callback deadlocks the event loop that delivers it.
func (s *Session) installFetchGate(tabCtx context.Context) error {
	chromedp.ListenTarget(tabCtx, func(ev any) {
		e, ok := ev.(*fetch.EventRequestPaused)
		if !ok {
			return
		}
		go func() {
			c := chromedp.FromContext(tabCtx)
			if c == nil || c.Target == nil {
				return
			}
			exec := cdp.WithExecutor(tabCtx, c.Target)
			u, err := url.Parse(e.Request.URL)
			if err == nil && (u.Scheme == "http" || u.Scheme == "https") {
				err = s.gate.AllowURL(u)
			} else if err == nil && (u.Scheme == "data" || u.Scheme == "blob" || u.Scheme == "about") {
				// Nothing leaves the machine for these.
				err = nil
			} else if err == nil {
				err = fmt.Errorf("scheme %q is not sent by a recorded login", u.Scheme)
			}
			if err != nil {
				s.recordBlocked(e.Request.Method + " " + RedactURL(e.Request.URL) + " — " + err.Error())
				_ = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(exec)
				return
			}
			_ = fetch.ContinueRequest(e.RequestID).Do(exec)
		}()
	})
	return chromedp.Run(tabCtx, fetch.Enable().WithPatterns([]*fetch.RequestPattern{
		{URLPattern: "*", RequestStage: fetch.RequestStageRequest},
	}))
}

// clearCookies empties the session's jar.
func (s *Session) clearCookies(ctx context.Context) error {
	ex, err := s.b.browserExecutor(ctx)
	if err != nil {
		return err
	}
	return storage.ClearCookies().WithBrowserContextID(s.id).Do(ex)
}

// Cookies returns every cookie in the session's jar.
func (s *Session) Cookies(ctx context.Context) ([]*network.Cookie, error) {
	ex, err := s.b.browserExecutor(ctx)
	if err != nil {
		return nil, err
	}
	return storage.GetCookies().WithBrowserContextID(s.id).Do(ex)
}

// RenderedDOMWithOptions is Browser.RenderedDOMWithOptions inside this session — the logged-in jar,
// and the session's gate.
func (s *Session) RenderedDOMWithOptions(ctx context.Context, targetURL string, opts RenderOptions) (string, RenderOutcome, error) {
	opts = opts.withDefaults()
	started := time.Now()
	var shot []byte
	html, reqs, dropped, err := s.b.renderedDOMIn(ctx, func(ctx context.Context) (context.Context, context.CancelFunc, error) {
		return s.newTab(ctx, s.b.opts.resolvedTimeout())
	}, targetURL, opts, &shot)
	outcome := RenderOutcome{Waited: time.Since(started), Requests: reqs, RequestsDropped: dropped, Screenshot: shot}
	if err != nil {
		return "", outcome, err
	}
	outcome.Settled = outcome.Waited < opts.MaxWait
	outcome.Capped = !outcome.Settled
	return html, outcome, nil
}

// ---- the gating proxy ---------------------------------------------------------------------------

type gateProxy struct {
	ln     net.Listener
	srv    *http.Server
	gate   ScopeGate
	record func(string)
	// transport sends the plain-HTTP requests the proxy allows. No proxy of its own: the session is
	// the proxy.
	transport *http.Transport
}

func startGateProxy(gate ScopeGate, record func(string)) (*gateProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("domexec: could not start the session's scope-gating proxy: %w", err)
	}
	p := &gateProxy{ln: ln, gate: gate, record: record, transport: &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false, ResponseHeaderTimeout: 30 * time.Second,
	}}
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = p.srv.Serve(ln) }()
	return p, nil
}

func (p *gateProxy) addr() string { return p.ln.Addr().String() }

func (p *gateProxy) close() {
	_ = p.srv.Close()
	p.transport.CloseIdleConnections()
}

func (p *gateProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.tunnel(w, r)
		return
	}
	if r.URL == nil || !r.URL.IsAbs() {
		http.Error(w, "burpsy session proxy: absolute-form requests only", http.StatusBadRequest)
		return
	}
	if err := p.gate.AllowURL(r.URL); err != nil {
		p.record(r.Method + " " + RedactURL(r.URL.String()) + " — " + err.Error())
		http.Error(w, "burpsy: refused by the engagement scope: "+err.Error(), http.StatusForbidden)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"} {
		out.Header.Del(h)
	}
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "burpsy session proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *gateProxy) tunnel(w http.ResponseWriter, r *http.Request) {
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "bad CONNECT authority", http.StatusBadRequest)
		return
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		http.Error(w, "bad CONNECT port", http.StatusBadRequest)
		return
	}
	// A CONNECT is TLS by Chrome's use of it (it tunnels plain HTTP only for WebSockets over ws://,
	// which this treats the same way: the authority is what is checked).
	if err := p.gate.AllowAuthority(strings.Trim(host, "[]"), uint16(port64), true); err != nil {
		p.record("CONNECT " + r.Host + " — " + err.Error())
		http.Error(w, "burpsy: refused by the engagement scope", http.StatusForbidden)
		return
	}
	upstream, err := net.DialTimeout("tcp", r.Host, 15*time.Second)
	if err != nil {
		http.Error(w, "burpsy session proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go pipe(upstream, client, buf)
	go pipe(client, upstream, nil)
}

func pipe(dst, src net.Conn, buffered *bufio.ReadWriter) {
	defer dst.Close()
	defer src.Close()
	if buffered != nil && buffered.Reader.Buffered() > 0 {
		pending, _ := buffered.Reader.Peek(buffered.Reader.Buffered())
		if _, err := dst.Write(pending); err != nil {
			return
		}
	}
	_, _ = io.Copy(dst, src)
}
