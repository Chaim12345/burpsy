// Package egressgate is burpsy's loopback scope-gating forward proxy: an HTTP proxy on 127.0.0.1 that
// a client burpsy does not control — a headless browser's isolated context, an external scanner
// binary — is pointed at, and that refuses every request the engagement scope does not authorise
// BEFORE it leaves the machine.
//
// It exists because the per-request byte gate burpsy applies to the requests it composes
// (sender.AuthorisedSender) cannot reach a request somebody else composes. A browser page loads
// whatever its markup names, and nuclei requests whatever its templates name; the only place left
// to stand is between that client and the network.
//
// What it can see, and therefore what it decides:
//
//   - A plain-HTTP request arrives in absolute form, so the gate sees the FULL URL — path and query —
//     and Gate.AllowURL decides it.
//   - An HTTPS request arrives as CONNECT host:port, and the TLS inside the tunnel is the client's own
//     end to end, so only the authority is visible and Gate.AllowAuthority decides it. Path-scoped
//     rules cannot be enforced on a tunnel here; a caller that needs them enforces them before it
//     starts the client (extscan.Authorise's subtree rule) or with an in-client hook as well
//     (domexec's Fetch interception).
//
// Every refusal is reported through the record callback and answered 403; nothing refused is
// dialled. Allowed traffic is dialled through the DialFunc the caller supplies — the sender's
// egress dialer in production (sender.Sender.EgressDialContext), so the operator's upstream proxy,
// SOCKS carrier and resolution table apply — or directly when none is given.
package egressgate

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Gate decides whether a request may be sent.
type Gate interface {
	// AllowURL is asked for every request whose full URL is visible. nil means allowed; an error is
	// the reason it is not.
	AllowURL(u *url.URL) error
	// AllowAuthority is asked for a CONNECT tunnel, where only host and port are visible.
	AllowAuthority(host string, port uint16, tls bool) error
}

// DialFunc opens one upstream TCP connection; net.Dialer.DialContext's signature.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialTimeout bounds a direct dial when no DialFunc is given, and every tunnel dial.
const DialTimeout = 15 * time.Second

// Proxy is one running gate.
type Proxy struct {
	ln     net.Listener
	srv    *http.Server
	gate   Gate
	record func(string)
	dial   DialFunc
	// transport sends the plain-HTTP requests the proxy allows. Its Proxy is nil on purpose — the
	// upstream route is dial's business, so a configured upstream is applied once, not twice.
	transport *http.Transport

	forwarded atomic.Int64
	refused   atomic.Int64
}

// Start listens on a fresh loopback port and serves until Close. record (may be nil) receives one
// line per refusal: "METHOD redacted-url — reason" or "CONNECT host:port — reason".
func Start(gate Gate, record func(string), dial DialFunc) (*Proxy, error) {
	if gate == nil {
		return nil, fmt.Errorf("egressgate: a gate is required")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("egressgate: could not start the scope-gating proxy: %w", err)
	}
	if record == nil {
		record = func(string) {}
	}
	if dial == nil {
		d := &net.Dialer{Timeout: DialTimeout}
		dial = d.DialContext
	}
	p := &Proxy{ln: ln, gate: gate, record: record, dial: dial, transport: &http.Transport{
		Proxy: nil, DialContext: dial, ForceAttemptHTTP2: false, ResponseHeaderTimeout: 30 * time.Second,
		// The client asked for exactly these bytes; transparently decompressing them would hand it a
		// different response from the one the server sent.
		DisableCompression: true,
	}}
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = p.srv.Serve(ln) }()
	return p, nil
}

// Addr is the proxy's host:port on loopback.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// URL is the proxy as an http:// URL, the form a client's proxy flag takes.
func (p *Proxy) URL() string { return "http://" + p.Addr() }

// Forwarded counts requests and tunnels the proxy let through.
func (p *Proxy) Forwarded() int64 { return p.forwarded.Load() }

// Refused counts requests and tunnels the gate refused.
func (p *Proxy) Refused() int64 { return p.refused.Load() }

// Close stops the listener and drops idle upstream connections. Tunnels already spliced end when
// either side closes.
func (p *Proxy) Close() {
	_ = p.srv.Close()
	p.transport.CloseIdleConnections()
}

func (p *Proxy) refuse(line string) {
	p.refused.Add(1)
	p.record(line)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.tunnel(w, r)
		return
	}
	if r.URL == nil || !r.URL.IsAbs() {
		http.Error(w, "burpsy egress gate: absolute-form requests only", http.StatusBadRequest)
		return
	}
	if r.URL.Scheme != "http" {
		p.refuse(r.Method + " " + RedactURL(r.URL.String()) + " — scheme " + strconv.Quote(r.URL.Scheme) + " is not proxied")
		http.Error(w, "burpsy: only plain http is forwarded; https goes through CONNECT", http.StatusForbidden)
		return
	}
	if err := p.gate.AllowURL(r.URL); err != nil {
		p.refuse(r.Method + " " + RedactURL(r.URL.String()) + " — " + err.Error())
		http.Error(w, "burpsy: refused by the engagement scope: "+err.Error(), http.StatusForbidden)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"} {
		out.Header.Del(h)
	}
	p.forwarded.Add(1)
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "burpsy egress gate: "+err.Error(), http.StatusBadGateway)
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

func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request) {
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
	// A CONNECT is TLS by every client's use of it here (a browser tunnels plain HTTP only for ws://,
	// which this treats the same way: the authority is what is checked).
	if err := p.gate.AllowAuthority(strings.Trim(host, "[]"), uint16(port64), true); err != nil {
		p.refuse("CONNECT " + r.Host + " — " + err.Error())
		http.Error(w, "burpsy: refused by the engagement scope", http.StatusForbidden)
		return
	}
	p.forwarded.Add(1)
	dialCtx, cancel := context.WithTimeout(r.Context(), DialTimeout)
	upstream, err := p.dial(dialCtx, "tcp", r.Host)
	cancel()
	if err != nil {
		http.Error(w, "burpsy egress gate: "+err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
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
		pending, _ := buffered.Peek(buffered.Reader.Buffered())
		if _, err := dst.Write(pending); err != nil {
			return
		}
	}
	_, _ = io.Copy(dst, src)
}

// RedactURL removes the values a URL may carry secrets in — query values, userinfo, the fragment — so
// a refusal can be recorded and shown without leaking a token. Unparseable input loses everything
// after its first ? or #.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		if i := strings.IndexAny(raw, "?#"); i >= 0 {
			return raw[:i] + "?…"
		}
		return raw
	}
	if u.RawQuery != "" {
		parts := strings.Split(u.RawQuery, "&")
		for i, p := range parts {
			name, _, hasValue := strings.Cut(p, "=")
			if hasValue {
				parts[i] = name + "=…"
			}
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	hadFragment := u.Fragment != "" || u.RawFragment != ""
	u.Fragment, u.RawFragment = "", ""
	u.User = nil
	out := u.String()
	if hadFragment {
		out += "#…"
	}
	return out
}
