package web

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// The proxy listener's runtime surface (burpsy-react-ui-77m, decision recorded on the
// issue: scope (1), one re-bindable listener). Burp's "Proxy listeners" panel starts
// with Binding, and burpsy's console offered nothing but a read-only metric — the bind
// was a flag read once at startup, and the only way to change it was to restart the
// process.
//
// This endpoint answers the live address — the one the accept loop actually serves,
// ephemeral ports resolved — and PUT re-binds it. The engine opens the new socket
// before closing the old one, so a failed bind is an error the operator sees, not an
// outage; see proxy.Server.Rebind. The listener is NOT persisted: -proxy-bind stays
// authoritative at boot, and a saved port that fights the flag would leave the panel
// describing a listener that exists only in the durable store.
//
// Invisible proxying (Burp's "Support invisible proxying (enable only if needed)") is
// a live option on the same set as the response rules — invisible_proxy on
// /api/proxy/options — because it is a relay behaviour, not a socket property, and it
// rides the endpoint that already persists option state.

// proxyListenerView is one GET's answer. PreviousBind is empty unless this process
// has re-bound the listener since it started.
type proxyListenerView struct {
	Bind         string `json:"bind"`
	PreviousBind string `json:"previous_bind,omitempty"`
}

// handleProxyListener serves GET/PUT /api/proxy/listener.
func (s *Server) handleProxyListener(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.proxyServer == nil {
			http.Error(w, "No proxy server is attached to this server, so there is no listener to inspect", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, proxyListenerView{Bind: s.proxyServer.ListenerAddr()})

	case http.MethodPut:
		if s.proxyServer == nil {
			http.Error(w, "No proxy server is attached to this server, so there is no listener to re-bind", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			Bind string `json:"bind"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Body must be JSON: {\"bind\": \"host:port\"}", http.StatusBadRequest)
			return
		}
		addr, err := normalizeListenerAddr(req.Bind)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		previous, err := s.proxyServer.Rebind(addr)
		if err != nil {
			// The old listener is still serving — the engine opened the new socket
			// first — so this is a failed request, not a failed listener.
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, proxyListenerView{Bind: s.proxyServer.ListenerAddr(), PreviousBind: previous})

	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// normalizeListenerAddr validates the bind string the PUT body carries. host:port is
// required — a portless address would silently mean :80 — and the port must be a real
// TCP port or 0, the one value that means "pick an ephemeral port" and is what the
// tests and the console's re-bind default to.
func normalizeListenerAddr(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("bind address is required, in host:port form")
	}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return "", errors.New("bind address must be host:port, e.g. 127.0.0.1:8080")
	}
	if host == "" {
		return "", errors.New("bind address needs a host: \"\" binds nothing; use 0.0.0.0 for every interface")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return "", errors.New("bind port must be a number between 0 and 65535")
	}
	return net.JoinHostPort(host, portStr), nil
}
