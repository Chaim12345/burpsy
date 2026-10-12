package scanner

// A short-lived local HTTP server for the two JWT rows that need the target to fetch material
// we chose.
//
// `jku` and `x5u` name a URL the server is supposed to fetch a key or certificate from. Proving
// the header is honoured means the target has to reach a URL we control and come back with a
// token we signed against what it found there. The out-of-band channel registers a callback
// domain but cannot serve chosen bytes, which is why this exists.
//
// # What this cannot do, and says so
//
// The target has to be able to reach the listener. Against a target on another network it
// cannot, and no fetch arrives — which is indistinguishable from a server that ignores the
// header. Both checks therefore report a finding only on a *confirmed* fetch plus an accepted
// token, and report the unreachable case as an explicit refusal rather than as a clean result.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// hostedMaterial is a one-shot server serving a single document.
type hostedMaterial struct {
	srv      *http.Server
	url      string
	fetched  atomic.Bool
	fetchLog []string
	mu       sync.Mutex
	// contentType and body are the document served, replaceable by Serve; guarded by mu.
	contentType string
	body        []byte
}

// Serve replaces the document at the same URL. The token's header names that URL before the
// material it points at exists, so the listener has to stay up while the material is created:
// closing it and listening again on the same port (as this once did) let any other listener in the
// process take the port in between, and the check then failed with no fetch to show.
func (h *hostedMaterial) Serve(contentType string, body []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.contentType, h.body = contentType, body
}

// hostMaterial starts a listener serving body at a random path, on all interfaces so a target
// on the same network can reach it.
func hostMaterial(contentType string, body []byte) (*hostedMaterial, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("jwks host: cannot listen: %w", err)
	}
	path := "/" + strings.ToLower(domCanary("jwks")) + ".json"
	h := &hostedMaterial{contentType: contentType, body: body}

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		h.fetched.Store(true)
		h.mu.Lock()
		h.fetchLog = append(h.fetchLog, r.RemoteAddr+" "+r.UserAgent())
		ct, b := h.contentType, h.body
		h.mu.Unlock()
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(b)
	})
	h.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	addr := ln.Addr().(*net.TCPAddr)
	host := localAdvertisableAddr()
	h.url = "http://" + net.JoinHostPort(host, fmt.Sprintf("%d", addr.Port)) + path

	go func() { _ = h.srv.Serve(ln) }()
	return h, nil
}

// Fetched reports whether the target actually retrieved the document.
func (h *hostedMaterial) Fetched() bool { return h != nil && h.fetched.Load() }

// FetchLog describes who fetched it, for the finding's evidence.
func (h *hostedMaterial) FetchLog() []string {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string{}, h.fetchLog...)
}

func (h *hostedMaterial) Close() {
	if h == nil || h.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = h.srv.Shutdown(ctx)
}

// localAdvertisableAddr picks an address a target could plausibly dial. Loopback is returned
// only as a last resort, because a remote target cannot reach it — and a check that advertises
// 127.0.0.1 to a remote host is guaranteed never to see a fetch.
func localAdvertisableAddr() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
			continue
		}
		return ipnet.IP.String()
	}
	return "127.0.0.1"
}

// jwtHostedCheck builds the jku (jwks=true) or x5u (jwks=false) evaluator. It decides by the same
// two-control differential as the other forgery rows (jwt_attacks.go), and stands down when the
// signature is not checked at all: that is one defect, reported once by "JWT signature not verified".
func jwtHostedCheck(row string, jwks bool) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		p, ok, err := newJWTProbe(ctx, cc, row)
		if err != nil || !ok {
			return nil, err
		}
		if !p.decidable() || p.garbageAccepted {
			return nil, nil
		}
		if s, err := p.stripped(ctx); err != nil {
			return nil, fmt.Errorf("%s: %w", row, err)
		} else if s {
			return nil, nil
		}

		// The token's header names the URL before the material it points at exists, so the
		// listener starts first and the forged material is served from it afterwards.
		host, hostErr := hostMaterial("application/json", []byte("{}"))
		if hostErr != nil {
			return nil, hostErr
		}
		defer host.Close()

		var forged, contentType string
		var material []byte
		if jwks {
			forged, material, err = ForgeWithJku(p.token, host.url)
			contentType = "application/json"
		} else {
			forged, material, err = ForgeWithX5u(p.token, host.url)
			contentType = "application/x-pem-file"
		}
		if err != nil {
			return nil, fmt.Errorf("%s: could not forge a token to test with: %w", row, err)
		}
		host.Serve(contentType, material)

		accepted, sendErr := p.accepted(ctx, forged)
		if sendErr != nil {
			return nil, fmt.Errorf("%s: %w", row, sendErr)
		}

		// The target has to have fetched the document for the header to have been honoured.
		// Acceptance without a fetch is some other reason the response matched, and saying
		// so is the difference between a finding and a guess.
		if !host.Fetched() {
			return nil, fmt.Errorf("%s: the target never fetched %s, so the header could not be shown to be honoured (a target that cannot reach this scanner will always look this way)",
				row, host.url)
		}
		if !accepted {
			return nil, nil
		}
		if ok, err := p.confirm(ctx, forged); err != nil || !ok {
			return nil, err
		}
		return []*Finding{buildHeaderFinding(cc, row, "high", "certain", forged,
			fmt.Sprintf("the target fetched key material from %s and accepted a token signed against it (HTTP %d, twice, "+
				"while an altered signature was rejected); fetchers: %s",
				host.url, p.baseCode, strings.Join(host.FetchLog(), "; ")))}, nil
	}
}
