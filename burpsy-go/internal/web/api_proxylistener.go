package web

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"

	"github.com/burpsy-go/burpsy/internal/proxy"
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
//
// # The collection (burpsy-react-ui-pfeg)
//
// Burp's panel is a LIST of listeners, each with its own "Redirect to host", "Redirect to
// port", "Force use of TLS" and "Support invisible proxying"; one bound address could not
// express the setup those controls exist for. This endpoint now carries that collection.
//
// The wire shape diverges from the bead's sketch, deliberately and for a reason worth
// stating: the sketch asked for /api/proxy/listeners plus /api/proxy/listeners/{id}, and the
// mux registers "/api/proxy/listener" as an exact-match pattern in server.go — a file this
// change does not own and which another agent has uncommitted work in. So the collection
// rides the one route this file owns, addressed by a query parameter:
//
//	GET    /api/proxy/listener          -> {bind, previous_bind?, listeners: [...]}
//	PUT    /api/proxy/listener          -> the legacy re-bind of the boot listener, {bind}
//	PUT    /api/proxy/listener?id=<id>  -> replace that listener's whole spec
//	POST   /api/proxy/listener          -> add a listener, 201 with the listener as it bound
//	DELETE /api/proxy/listener?id=<id>  -> remove a listener
//
// The bodiless legacy contract (GET's bind/previous_bind, PUT {bind}) is unchanged to the
// byte, because the in-browser panel and the existing tests read it.
//
// Nothing here is persisted, for the reason the single bind was not: -proxy-bind is
// authoritative at boot and a saved listener set that fought the flag would leave the panel
// describing sockets that exist only in a durable store. The console says so.

// proxyListenerRow is one listener on the wire.
//
// Invisible is a *bool and nullable on the wire on purpose: null means "inherit the
// process-wide invisible_proxy switch", which is what the boot listener is and what keeps an
// operator who never opens this page on exactly the behaviour they had. A plain bool would
// have made the per-listener tick a no-op, since invisible_proxy is seeded on.
type proxyListenerRow struct {
	ID           string `json:"id"`
	Bind         string `json:"bind"`
	BoundAddr    string `json:"bound_addr"`
	RedirectHost string `json:"redirect_host"`
	RedirectPort uint16 `json:"redirect_port"`
	ForceTLS     bool   `json:"force_tls"`
	Invisible    *bool  `json:"invisible"`
	Removable    bool   `json:"removable"`
}

// proxyListenerView is one GET's answer. PreviousBind is empty unless this process
// has re-bound the listener since it started. Listeners is never null — the console reads
// .length off it, and a nil slice would reach the browser as JSON null and take the view
// down.
type proxyListenerView struct {
	Bind         string             `json:"bind"`
	PreviousBind string             `json:"previous_bind,omitempty"`
	Listeners    []proxyListenerRow `json:"listeners"`
}

// proxyListenerBody is what POST and the id-addressed PUT carry. Every field is optional on
// a POST except bind; an omitted invisible means "inherit".
type proxyListenerBody struct {
	Bind         string  `json:"bind"`
	RedirectHost string  `json:"redirect_host"`
	RedirectPort *int    `json:"redirect_port"`
	ForceTLS     *bool   `json:"force_tls"`
	Invisible    *bool   `json:"invisible"`
	ID           *string `json:"id"`
}

// listenerRows renders the engine's collection for the wire, always as a non-nil slice.
func listenerRows(statuses []proxy.ListenerStatus) []proxyListenerRow {
	rows := make([]proxyListenerRow, 0, len(statuses))
	for _, st := range statuses {
		rows = append(rows, proxyListenerRow{
			ID:           st.ID,
			Bind:         st.Bind,
			BoundAddr:    st.BoundAddr,
			RedirectHost: st.RedirectHost,
			RedirectPort: st.RedirectPort,
			ForceTLS:     st.ForceTLS,
			Invisible:    st.Invisible,
			Removable:    st.ID != proxy.BootListenerID,
		})
	}
	return rows
}

// specFromBody validates one listener's settings. It refuses rather than repairs: a bind it
// cannot mean, a redirect host with a scheme or an embedded port, a port outside the range —
// each is the caller's mistake and each is worth an answer now instead of a listener that
// looks configured and relays somewhere else.
func specFromBody(body proxyListenerBody) (proxy.ListenerSpec, error) {
	addr, err := normalizeListenerAddr(body.Bind)
	if err != nil {
		return proxy.ListenerSpec{}, err
	}
	host, err := proxy.NormalizeRedirectHost(body.RedirectHost)
	if err != nil {
		return proxy.ListenerSpec{}, err
	}
	var redirectPort uint16
	if body.RedirectPort != nil {
		if *body.RedirectPort < 0 || *body.RedirectPort > 65535 {
			return proxy.ListenerSpec{}, errors.New("redirect port must be between 0 and 65535; 0 means keep the port the client asked for")
		}
		redirectPort = uint16(*body.RedirectPort)
	}
	spec := proxy.ListenerSpec{
		Bind:         addr,
		RedirectHost: host,
		RedirectPort: redirectPort,
		Invisible:    body.Invisible,
	}
	if body.ForceTLS != nil {
		spec.ForceTLS = *body.ForceTLS
	}
	return spec, nil
}

// listenerBindStatus tells a bind conflict ("this port is taken") apart from a caller's own
// mistake, the same distinction the legacy PUT has made since burpsy-react-ui-459i.
func listenerBindStatus(err error) int {
	if errors.Is(err, syscall.EADDRINUSE) {
		return http.StatusConflict
	}
	return http.StatusBadRequest
}

// proxyListenerReq is the request body handleProxyListener decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type proxyListenerReq struct {
	Bind string `json:"bind"`
}

// handleProxyListener serves GET/PUT/POST/DELETE /api/proxy/listener.
func (s *Server) handleProxyListener(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.proxyServer == nil {
			http.Error(w, "No proxy server is attached to this server, so there is no listener to inspect", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, proxyListenerView{
			Bind:      s.proxyServer.ListenerAddr(),
			Listeners: listenerRows(s.proxyServer.Listeners()),
		})

	case http.MethodPut:
		// An id names one listener in the collection and replaces its whole spec; without
		// one this is the legacy re-bind of the boot listener, unchanged. Each body is decoded
		// before the proxy check so the schema sweep reaches it (burpsy-react-ui-3zw0).
		if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
			s.updateProxyListener(w, r, id)
			return
		}
		var req proxyListenerReq
		if err := requestJSON(w, r, nil).Decode(&req); err != nil {
			http.Error(w, "Body must be JSON: {\"bind\": \"host:port\"}", http.StatusBadRequest)
			return
		}
		if s.proxyServer == nil {
			http.Error(w, "No proxy server is attached to this server, so there is no listener to re-bind", http.StatusServiceUnavailable)
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
			//
			// Every Rebind failure used to answer 400 here (burpsy-react-ui-459i), though the
			// close note on -77m already claimed the 409 this restores: "this port is already
			// taken" is a state conflict the caller can resolve by picking another address, and
			// is worth telling apart from "this address is malformed or unresolvable", which is
			// the caller's own mistake. net.Listen wraps the dial-level error with %w (see
			// proxy.Server.Rebind), so errors.Is sees through the wrapping to the syscall errno
			// without this package needing to parse the message text.
			http.Error(w, err.Error(), listenerBindStatus(err))
			return
		}
		writeJSON(w, http.StatusOK, proxyListenerView{
			Bind:         s.proxyServer.ListenerAddr(),
			PreviousBind: previous,
			Listeners:    listenerRows(s.proxyServer.Listeners()),
		})

	case http.MethodPost:
		var body proxyListenerBody
		if err := requestJSON(w, r, nil).Decode(&body); err != nil {
			http.Error(w, "Body must be JSON: {\"bind\": \"host:port\", \"redirect_host\": …, \"redirect_port\": …, \"force_tls\": …, \"invisible\": …}", http.StatusBadRequest)
			return
		}
		if s.proxyServer == nil {
			http.Error(w, "No proxy server is attached to this server, so a listener cannot be added", http.StatusServiceUnavailable)
			return
		}
		spec, err := specFromBody(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		status, err := s.proxyServer.AddListener(spec)
		if err != nil {
			// A listener that cannot bind is refused with the reason, and nothing is added.
			// The alternative — recording it and letting it sit there dead — is the state
			// this endpoint exists to make impossible: every row the GET returns is a
			// socket the accept loop is serving.
			if errors.Is(err, proxy.ErrNotListening) {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			http.Error(w, err.Error(), listenerBindStatus(err))
			return
		}
		writeJSON(w, http.StatusCreated, listenerRows([]proxy.ListenerStatus{status})[0])

	case http.MethodDelete:
		if s.proxyServer == nil {
			http.Error(w, "No proxy server is attached to this server, so there is no listener to remove", http.StatusServiceUnavailable)
			return
		}
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "Which listener? DELETE /api/proxy/listener?id=<id>", http.StatusBadRequest)
			return
		}
		switch err := s.proxyServer.RemoveListener(id); {
		case err == nil:
		case errors.Is(err, proxy.ErrNoSuchListener):
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		case errors.Is(err, proxy.ErrBootListenerNotRemovable):
			// 409, not 403: the request is well-formed and the caller is allowed to ask —
			// it is the collection's state (this is the listener -proxy-bind opened) that
			// refuses, and re-binding it is the resolution.
			http.Error(w, err.Error(), http.StatusConflict)
			return
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, proxyListenerView{
			Bind:      s.proxyServer.ListenerAddr(),
			Listeners: listenerRows(s.proxyServer.Listeners()),
		})

	default:
		w.Header().Set("Allow", "GET, PUT, POST, DELETE")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// updateProxyListener replaces one listener's whole spec. A bind that changed moves the
// socket the way the legacy re-bind does — new socket first, so a failure leaves the
// listener serving and is an error the operator reads, never a dead row.
func (s *Server) updateProxyListener(w http.ResponseWriter, r *http.Request, id string) {
	var body proxyListenerBody
	if err := requestJSON(w, r, nil).Decode(&body); err != nil {
		http.Error(w, "Body must be JSON: {\"bind\": \"host:port\", \"redirect_host\": …, \"redirect_port\": …, \"force_tls\": …, \"invisible\": …}", http.StatusBadRequest)
		return
	}
	if s.proxyServer == nil {
		http.Error(w, "No proxy server is attached to this server, so there is no listener to re-bind", http.StatusServiceUnavailable)
		return
	}
	spec, err := specFromBody(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	status, err := s.proxyServer.UpdateListener(id, spec)
	if err != nil {
		if errors.Is(err, proxy.ErrNoSuchListener) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), listenerBindStatus(err))
		return
	}
	writeJSON(w, http.StatusOK, listenerRows([]proxy.ListenerStatus{status})[0])
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
