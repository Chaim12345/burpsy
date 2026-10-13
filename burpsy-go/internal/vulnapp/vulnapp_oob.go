package vulnapp

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Out-of-band fixtures (burpsy-react-ui-ar8v), not manifest rows.
//
// /oob/fetch is a server-side request forgery: it "fetches" whatever its url parameter names. It
// does not touch the network — nothing in this package may — but records the contact it would have
// made in OutboundContacts: the DNS lookup of the host, then the HTTP request to it. A test's
// in-process collaborator reads that log the way a real interaction server reads its own, so a
// collaborator check can be proven to fire against the vulnerable endpoint and stay quiet on
// /safe/oob/fetch, which fetches only from an allowlist.
//
// They are deliberately absent from Vulnerabilities(). The runtime suite has no interaction server,
// so a row here would fail for the right reason and read as a regression; and the finding a BCheck
// reports is named by the check, not by a catalogue row. Run by hand (cmd/demo-target), the
// endpoint calls nobody: a real collaborator will never see it, which is the point of "no real
// damage, ever".

// OutboundContact is one contact /oob/fetch would have made.
type OutboundContact struct {
	// Protocol is "dns" or "http".
	Protocol string
	// Host is the host contacted, as the request named it.
	Host string
}

// maxOutboundContacts bounds the log, so a long-running demo target cannot grow it without limit.
const maxOutboundContacts = 4096

var outbound struct {
	mu  sync.Mutex
	log []OutboundContact
}

// OutboundContacts returns every contact recorded so far, oldest first.
func OutboundContacts() []OutboundContact {
	outbound.mu.Lock()
	defer outbound.mu.Unlock()
	return append([]OutboundContact(nil), outbound.log...)
}

func recordContact(protocol, host string) {
	outbound.mu.Lock()
	defer outbound.mu.Unlock()
	if len(outbound.log) >= maxOutboundContacts {
		outbound.log = outbound.log[1:]
	}
	outbound.log = append(outbound.log, OutboundContact{Protocol: protocol, Host: host})
}

// oobAllowedHosts is the safe twin's allowlist.
var oobAllowedHosts = map[string]bool{"cdn.example.test": true}

// fetchTargetHost reads the host a url parameter names, accepting a bare host the way a careless
// fetcher prepends a scheme to one.
func fetchTargetHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + strings.TrimPrefix(raw, "//")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func registerOOBFixtures(mux *http.ServeMux) {
	mux.HandleFunc("/oob/fetch", oobFetch)
	mux.HandleFunc("/safe/oob/fetch", safeOOBFetch)
	registerOOBSQLFixtures(mux)
}

// oobFetch resolves and "requests" any host it is handed.
func oobFetch(w http.ResponseWriter, r *http.Request) {
	host := fetchTargetHost(r.URL.Query().Get("url"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if host == "" {
		fmt.Fprint(w, "<html><body><p>nothing to fetch</p></body></html>")
		return
	}
	recordContact("dns", host)
	recordContact("http", host)
	// The response says nothing about the fetch: the only evidence is out of band, which is what
	// makes this a collaborator fixture rather than a reflection one.
	fmt.Fprint(w, "<html><body><p>preview queued</p></body></html>")
}

// safeOOBFetch fetches only allowlisted hosts and contacts nobody else.
func safeOOBFetch(w http.ResponseWriter, r *http.Request) {
	host := fetchTargetHost(r.URL.Query().Get("url"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if host != "" && oobAllowedHosts[host] {
		recordContact("dns", host)
		recordContact("http", host)
	}
	fmt.Fprint(w, "<html><body><p>preview queued</p></body></html>")
}
