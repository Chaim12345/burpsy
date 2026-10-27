package scanner

// The scope gate every scanner-driven browser render runs under (burpsy-react-ui-browser-render-unscoped).
//
// A render used to be authorised by its top-level URL alone: the crawl audit pass and the CSTI check
// pointed the shared browser at an in-scope page, and the page then loaded whatever it liked —
// scripts, beacons, XHR, frames — from any host. domexec.Browser.RenderedDOMGated now checks every one
// of those requests; this file is what it checks them against.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
)

// renderScopeGate authorises a render's requests.
//
// With a declared engagement scope (rules, or allow-all) a request is allowed when the scope
// authorises it as a composed request — AuthoriseRaw on the request line it would send, so excludes,
// path prefixes and the custom drop scope all apply. With NO declared scope, only the origin the
// render was pointed at is allowed: an empty scope's "default allow" is a statement about what the
// operator retains, not a licence for a page to drag the scanner's browser to every third party it
// references.
type renderScopeGate struct {
	scope  *core.Scope
	scheme string
	host   string
	port   uint16
}

// newRenderScopeGate builds the gate for rendering target under scope.
func newRenderScopeGate(scope *core.Scope, target string) (renderScopeGate, error) {
	u, err := url.Parse(target)
	if err != nil {
		return renderScopeGate{}, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return renderScopeGate{}, fmt.Errorf("%q is not an http(s) URL", target)
	}
	g := renderScopeGate{scheme: u.Scheme, host: strings.ToLower(u.Hostname()), port: urlPort(u)}
	if scope != nil && (!scope.Empty() || scope.AllowAll()) {
		g.scope = scope
	}
	return g, nil
}

func urlPort(u *url.URL) uint16 {
	if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 && p < 65536 {
		return uint16(p)
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

func (g renderScopeGate) AllowURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q is not rendered", u.Scheme)
	}
	host, port, tls := strings.ToLower(u.Hostname()), urlPort(u), u.Scheme == "https"
	if g.scope == nil {
		if u.Scheme != g.scheme || host != g.host || port != g.port {
			return errors.New("no engagement scope is declared, so a render may reach only the page's own origin")
		}
		return nil
	}
	uri := u.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	if u.RawQuery != "" {
		uri += "?" + u.RawQuery
	}
	return g.scope.AuthoriseRaw(host, port, tls, []byte("GET "+uri+" HTTP/1.1\r\nHost: "+u.Host+"\r\n\r\n"))
}

func (g renderScopeGate) AllowAuthority(host string, port uint16, tls bool) error {
	host = strings.ToLower(host)
	if g.scope == nil {
		if host != g.host || port != g.port {
			return errors.New("no engagement scope is declared, so a render may reach only the page's own origin")
		}
		return nil
	}
	if !g.scope.MayContainHost(host, port, tls) {
		return errors.New("host out of scope")
	}
	return nil
}

// gatedRenderer adapts a Browser to cstiRenderer, gating every render on the engagement scope.
type gatedRenderer struct {
	browser *domexec.Browser
	scope   *core.Scope
}

func (r gatedRenderer) RenderedDOMWithOptions(ctx context.Context, targetURL string, opts domexec.RenderOptions) (string, domexec.RenderOutcome, error) {
	gate, err := newRenderScopeGate(r.scope, targetURL)
	if err != nil {
		return "", domexec.RenderOutcome{}, err
	}
	return r.browser.RenderedDOMGated(ctx, targetURL, opts, gate)
}
