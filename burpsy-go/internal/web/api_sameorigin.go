package web

import (
	"net"
	"net/http"
	"strings"
)

// ---- cross-site request protection on the console (burpsy-react-ui-s19k) --------------------------
//
// # The problem
//
// burpsy's console has no authentication. It is a tool that sends attacks — it starts audits, submits
// requests from Repeater, writes scope rules, reads cookies and session material — and it binds to
// 127.0.0.1 by default, which stops other HOSTS but not the operator's own BROWSER, which visits
// hostile targets all day while burpsy runs.
//
// Three live paths, and the loopback bind defeats only the first:
//
//   - CSRF. A page the operator visits issues a cross-origin request to http://127.0.0.1:8081/api/....
//     With no origin check and no content-type requirement, a form or a fetch can start an audit or
//     widen the scope.
//   - DNS rebinding. A hostile domain resolves to 127.0.0.1, so the browser treats the console as
//     SAME-ORIGIN and the Origin header says nothing. The Host header is the only signal left.
//   - A non-loopback bind (`-web 0.0.0.0:8081`, a documented flag) puts the whole console on the
//     network with no credential at all.
//
// # What this gate does, and what it deliberately does not
//
// It validates the REQUESTER, not the requester's permission:
//
//   - Host must be a loopback name/address, or one this server was told to accept. That is the
//     rebinding defence, and it is the only one of the three that rebinding cannot route around.
//   - Sec-Fetch-Site, when present, must be same-origin, same-site or none. That is the modern
//     signal, set by the browser itself and not forgeable by page script.
//   - Origin, when present, must match the Host the request arrived on. That is the fallback for
//     browsers that send no Sec-Fetch-Site, and it is also forgeable only by a non-browser client —
//     which is fine, because a non-browser client is a script the operator wrote.
//
// THE HOST CHECK APPLIES TO EVERY METHOD; the Sec-Fetch-Site and Origin checks apply only to the
// mutating verbs (POST, PUT, PATCH, DELETE). The split is the rebinding case
// (burpsy-react-ui-rebind-read): a page on a domain that rebinds to 127.0.0.1 is SAME-ORIGIN to the
// browser, so it can not only send a GET but READ the reply — /api/message/{id} hands it captured
// cookies and session material, /api/history the operator's whole traffic. Same-origin policy is
// what normally stops a hostile page reading a cross-origin GET, and rebinding is exactly the attack
// that switches it off, so a read is only safe once Host shows the browser was pointed at THIS
// console. A plain cross-origin GET (not rebound) is still allowed: it cannot change state, the page
// cannot read the reply, and refusing it would break the CA download and a bookmarked page.
//
// # Why a token is NOT implemented here, and what would be needed
//
// A per-instance bearer token is the right answer to the non-loopback-bind case, and it is not
// implemented because it is a UX decision with no safe default: printing a token at startup and making
// the console hold it means the operator cannot bookmark the console or open it on a second machine
// without a deliberate step, and this project has shipped every other bound as a flag with a working
// default. The gate below needs no such step and stops both browser-driven attacks. The residual —
// anyone who can reach a non-loopback bind can still read the console — is stated in the docs rather
// than papered over, and the honest fix is a flag, not a silent default.
//
// # Why this lives in setupRoutes and not ListenAndServe
//
// Every test in this package builds a Server with NewServer and drives `s.mux.ServeHTTP` directly, so
// a gate in the ListenAndServe wrapper would be exercised by nothing and verified by nothing — a
// security control that the test suite cannot see is a comment, not a control. Wrapping the mux where
// the routes are registered makes it impossible to add a route that bypasses it.

// sameOriginHosts is the set of Host header values a loopback-bound console answers to.
//
// The PORT is included because Host carries it. A request to 127.0.0.1:8081 sends that exact host, so
// comparing the whole value is what makes the check a rebinding defence rather than a hostname
// comparison an attacker can satisfy by sending a bare address.
var sameOriginHosts = map[string]bool{
	"127.0.0.1:": true, "localhost:": true, "[::1]:": true,
}

// isLoopbackHost reports whether h names the loopback interface, on any port.
//
// SplitHostPort rather than a prefix match: a rebinding attack controls the NAME, so the check has to
// be on the resolved shape of the value, not on whether it starts with "localhost" — "localhost.evil.com"
// does, and 127.0.0.1.evil.com does too.
func isLoopbackHost(h string) bool {
	host := h
	if hp, _, err := net.SplitHostPort(h); err == nil {
		host = hp
	}
	// A bare name with no port: SplitHostPort fails, and the value is still checked as a host.
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// mutatingVerbs are the methods the Sec-Fetch-Site and Origin checks apply to. GET and HEAD are
// absent because a cross-origin GET cannot change server state and its reply is unreadable to the
// page that sent it, and blocking it would break the CA download and every page reload. The Host check
// is NOT limited to these verbs: see requireSameOrigin.
var mutatingVerbs = map[string]bool{
	http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
}

// requireSameOrigin refuses a request that did not come from this console.
//
// Three checks, in the order that costs least, and each is sufficient on its own for the attack it
// answers. All three pass for the console's own fetch(), which is same-origin, sends no cross-origin
// Origin header, and sets Sec-Fetch-Site: same-origin. The Host check runs on EVERY method; the other
// two only on a mutating one.
func (s *Server) requireSameOrigin(w http.ResponseWriter, r *http.Request) bool {
	// 1. Host. The rebinding defence, and the only one rebinding cannot route around: a hostile
	//    domain that rebinds to 127.0.0.1 still sends ITS OWN name in Host, so the browser's
	//    same-origin view and this check disagree, and this check is the one that holds.
	//
	//    Before the method test, not after it (burpsy-react-ui-rebind-read). A rebound page is
	//    same-origin to the browser, so a GET it sends is one whose reply it can READ — captured
	//    cookies from /api/message/{id}, the whole proxy history from /api/history. Exempting reads
	//    here exempted exactly the requests the rebinding attack exists to make.
	host := r.Host
	if !s.acceptsHost(host) {
		http.Error(w, crossSiteRefusal, http.StatusForbidden)
		return false
	}
	if !mutatingVerbs[r.Method] {
		return true
	}

	// 2. Sec-Fetch-Site. Set by the browser and not readable by page script, so a hostile page
	//    cannot forge it. "none" is a user-initiated navigation (a typed URL, a bookmark), which is
	//    legitimately not same-origin and is exactly the case that must be allowed.
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "same-site", "none":
	default:
		http.Error(w, crossSiteRefusal, http.StatusForbidden)
		return false
	}

	// 3. Origin, for the browsers that send no Sec-Fetch-Site. A cross-origin form post sends the
	//    hostile page's origin here, which is the signal. Absent is allowed: same-origin fetches do
	//    not send Origin on every method, and requiring it would refuse the console's own calls.
	if origin := r.Header.Get("Origin"); origin != "" && !s.originMatchesHost(origin, host) {
		http.Error(w, crossSiteRefusal, http.StatusForbidden)
		return false
	}
	return true
}

// acceptsHost reports whether the console answers to this Host header.
//
// Loopback is always accepted: a loopback name or address in Host is not something a rebinding
// attack can produce, because rebinding needs the browser to be pointed at the ATTACKER'S name. On top
// of that, the configured allowlist — names the operator gave (WithAllowedHosts) and the address the
// console was bound to (allowBindAddr) — keeps a non-loopback bind usable. A configured list used to
// REPLACE loopback; that was harmless while a GET was never checked, and once the Host check covered
// reads (burpsy-react-ui-rebind-read) it would have locked the operator's own loopback browser out of
// a console they bound to 0.0.0.0.
func (s *Server) acceptsHost(host string) bool {
	if isLoopbackHost(host) {
		return true
	}
	return s.allowedHosts[host] || s.allowedHosts[stripPort(host)]
}

// localInterfaceAddrs is what ListenAndServe enumerates for a wildcard bind. A variable so a test can
// state the interfaces rather than depend on the machine it runs on.
var localInterfaceAddrs = net.InterfaceAddrs

// allowBindAddr adds the Host values a browser legitimately sends to a console bound at addr.
//
// A specific address or name is accepted as written, with its port: `-web 192.168.1.5:8081` is the
// operator naming exactly what they will type. A wildcard bind (`0.0.0.0:8081`, `[::]:8081`, `:8081`)
// is accepted on each of this machine's interface ADDRESSES with that port. Addresses only, never
// names: an IP literal in Host means the browser was pointed at that IP, which no DNS rebinding can
// arrange. A DNS name for a wildcard bind still has to be named with WithAllowedHosts.
//
// A failed interface enumeration adds nothing, so the console falls back to loopback only — the
// direction that refuses a legitimate remote browser rather than accepting a hostile one.
func (s *Server) allowBindAddr(addr string, interfaceAddrs func() ([]net.Addr, error)) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return
	}
	var hosts []string
	if ip := net.ParseIP(host); host != "" && (ip == nil || !ip.IsUnspecified()) {
		hosts = append(hosts, net.JoinHostPort(host, port))
	} else if interfaceAddrs != nil {
		addrs, err := interfaceAddrs()
		if err != nil {
			return
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLinkLocalUnicast() {
				// Link-local IPv6 needs a zone in Host, which no browser URL carries portably.
				continue
			}
			hosts = append(hosts, net.JoinHostPort(ipn.IP.String(), port))
		}
	}
	if len(hosts) > 0 {
		s.WithAllowedHosts(hosts...)
	}
}

// originMatchesHost reports whether an Origin header names the same authority the request arrived on.
func (s *Server) originMatchesHost(origin, host string) bool {
	// "null" is what a browser sends for a sandboxed iframe, a data: URL, or some redirects. It names
	// no origin, so it cannot be shown to be this one.
	if origin == "null" {
		return false
	}
	o := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	o = strings.TrimSuffix(o, "/")
	if o == "" {
		return false
	}
	// Compared on the authority, so a request that arrived on 127.0.0.1:8081 is not satisfied by an
	// Origin naming localhost:8081 — the two are different origins to a browser, even though both are
	// loopback, and treating them as one would reopen the rebinding case this exists to close.
	return o == host || o == stripPort(host) && hostIsPortOnly(o)
}

// stripPort removes a trailing :port from an authority that carries one.
func stripPort(h string) string {
	if hp, _, err := net.SplitHostPort(h); err == nil {
		return hp
	}
	return h
}

// hostIsPortOnly reports whether h is a bare port number, which cannot be a host an Origin names.
func hostIsPortOnly(h string) bool {
	return h != "" && !strings.Contains(h, ":") && !strings.Contains(h, ".")
}

// crossSiteRefusal is the body every refusal returns.
//
// It names the reason and says what to do, and it says NOTHING about the console's routes, its
// version, or whether a token exists. A refusal that explained the control would tell an attacker
// probing for it exactly which header to try next.
const crossSiteRefusal = "refused: this request did not come from burpsy's own console.\n" +
	"A page in your browser, or a domain that rebound to this address, tried to drive burpsy's API.\n" +
	"Open the console at its own address and act there."
