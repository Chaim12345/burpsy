package web

// The live passive crawl (burpsy-react-ui-t3zk), Burp's "Add all links observed in traffic through
// Proxy to site map": every link in an in-scope HTML page the operator's browser fetched through the
// proxy is added to the site map as an unrequested (grey) item, until something requests it. It sends
// nothing. Burp's "Reviewing unrequested items" workflow then has something to show.

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/crawler"
)

// ObserveProxiedPage is the proxy's page observer (proxy.ProxyConfig.WithPageObserver). It reads the
// response bytes the proxy already holds, never the store, because it runs on the capture path.
func (s *Server) ObserveProxiedPage(ex *core.Exchange, response []byte) {
	if s == nil || ex == nil || s.sitemap == nil || !isHTMLResponse(response) {
		return
	}
	if s.scope != nil && !s.scope.Contains(ex.Host, ex.Port, ex.Path, ex.TLS) {
		return
	}
	scheme := "http"
	if ex.TLS {
		scheme = "https"
	}
	base, err := url.Parse(scheme + "://" + hostPortFor(ex.Host, ex.Port, ex.TLS) + ex.Path)
	if err != nil {
		return
	}
	body := response
	if i := strings.Index(string(response), "\r\n\r\n"); i >= 0 {
		body = response[i+4:]
	}
	now := time.Now()
	for _, u := range crawler.LinkTargets(body, base) {
		port := u.Port()
		p := uint16(80)
		tls := u.Scheme == "https"
		if tls {
			p = 443
		}
		if port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n <= 0 || n > 65535 {
				continue
			}
			p = uint16(n)
		}
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
		if s.scope != nil && !s.scope.Contains(u.Hostname(), p, u.EscapedPath(), tls) {
			continue
		}
		s.sitemap.AddUnrequested(u.Hostname(), p, tls, path, base.String(), now)
	}
}

// isHTMLResponse reads the Content-Type of a raw response head.
func isHTMLResponse(raw []byte) bool {
	head := string(raw)
	if i := strings.Index(head, "\r\n\r\n"); i >= 0 {
		head = head[:i]
	}
	for _, line := range strings.Split(head, "\r\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Type") {
			return strings.Contains(strings.ToLower(v), "html")
		}
	}
	return false
}

func hostPortFor(host string, port uint16, tls bool) string {
	if (tls && port == 443) || (!tls && port == 80) || port == 0 {
		return host
	}
	return host + ":" + strconv.Itoa(int(port))
}
