package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// Burp's "Proxy listeners" panel is a LIST, not one socket (burpsy-react-ui-pfeg). Each row
// binds an address and carries its own relay behaviour: "Redirect to host", "Redirect to
// port", "Force use of TLS" and "Support invisible proxying". This file is that collection —
// the set of sockets the engine actually serves, each with the spec its connections are
// handled under.
//
// # Why a listener is a spec plus a socket, and not just a socket
//
// The engine had exactly one listener and one global option set, so a relay behaviour could
// only ever be process-wide. That is the wrong shape for the thing the panel is primarily
// for: pointing a non-proxy-aware client at a listener that forwards to some other origin,
// over TLS, while another listener on the next port stays an ordinary proxy. The spec
// travels with the connection — it is snapshotted at accept time, so an edit applies from
// the next connection and never mutates one already being relayed.
//
// # What is NOT here, deliberately
//
// Per-listener certificate configuration and TLS protocol selection (Burp's other two tabs
// on the same dialog) are a separate, larger item; the bead says so and they are filed
// apart. Nothing here is persisted, for the reason -77m gave about the single bind: the
// -proxy-bind flag stays authoritative at boot, and a saved listener set that fought the
// flag would leave the panel describing sockets that exist only in a durable store.

// bootListenerID names the listener -proxy-bind opens at startup. It is the one the legacy
// ListenerAddr/Rebind surface answers about (cmd/burpsy, cmd/desktop and the in-browser
// panel all lean on it), so it is re-bindable but not removable — see RemoveListener.
const BootListenerID = "default"

// bootListenerID is the package-internal spelling of the same constant.
const bootListenerID = BootListenerID

// ListenerSpec is one proxy listener as the operator configured it.
//
// The four behaviour fields are read by the relay on every connection this listener accepts;
// see redirectFor, forcesTLS and invisibleWith for exactly what each one does, which is the
// only place those questions are answered.
type ListenerSpec struct {
	// ID is stable for the life of the process and is what the API addresses a listener by.
	ID string
	// Bind is the address the operator asked for, host:port. The socket's resolved address
	// (an ephemeral :0 becomes a real port) is reported separately — see BoundAddr.
	Bind string
	// RedirectHost and RedirectPort are Burp's "Redirect to host" / "Redirect to port": the
	// destination every request arriving on this listener is sent to instead of the one the
	// client named. Empty host means "keep the client's host"; zero port means "keep the
	// client's port".
	RedirectHost string
	RedirectPort uint16
	// ForceTLS is Burp's "Force use of TLS": the connection this proxy opens to the
	// destination uses TLS whatever the client used to reach the listener.
	ForceTLS bool
	// Invisible is Burp's "Support invisible proxying", as a tri-state: nil inherits the
	// process-wide invisible_proxy option (the boot listener's value, so an operator who
	// never opens this page sees exactly the behaviour they had), true forces it on for this
	// listener alone and false forces it off for this listener alone.
	//
	// A plain bool would have made the per-listener control a no-op: invisible_proxy is
	// seeded ON, so a listener ticked off would still have accepted origin-form requests.
	Invisible *bool
	// CertMode is Burp's per-listener "Server TLS certificate" choice (burpsy-react-ui-4trc).
	// The zero value is CertModeCAPerHost, which is what every listener did before this field
	// existed: sign a leaf per requested hostname from the process CA.
	CertMode CertMode
	// CertHostname is the one name every leaf carries under CertModeCAFixed. Ignored in the other
	// modes. Empty under CertModeCAFixed is refused at validation rather than silently falling back
	// to per-host signing — a listener that was asked for a fixed name and quietly served the
	// client's own would be a control that reads as applied and does something else.
	CertHostname string
	// CertFile and CertPassword locate a PKCS#12 bundle for CertModePKCS12. The password is held
	// because the bundle is re-read when the listener is rebound; it is never logged and never
	// reported by the API — see ListenerStatus, which carries the spec but is built by
	// redactedSpec.
	CertFile     string
	CertPassword string
	// TLSMinVersion and TLSMaxVersion bound the protocol versions this listener offers a client,
	// as crypto/tls constants. Zero on either side means "the Go default", so a listener that names
	// neither behaves exactly as it did.
	//
	// A RANGE rather than a single version, because that is what the negotiation actually is:
	// crypto/tls picks the highest version both sides support inside [Min, Max]. A single "use
	// TLS 1.2" setting would either pin the connection to one version — breaking every client that
	// cannot speak it — or silently mean a floor, and an operator cannot tell which from the name.
	TLSMinVersion uint16
	TLSMaxVersion uint16
	// HTTP2 is Burp's per-listener "Support HTTP/2" (burpsy-react-ui-34rd). nil and true keep h2 in the
	// browser leg's ALPN offer, which is what every listener did before this existed. false drops it, so
	// a client with a broken h2 stack is held to HTTP/1.1 on this listener without turning interception
	// on. A pointer so an absent field cannot be read as "off".
	HTTP2 *bool
}

// http2Allowed reports whether this listener offers HTTP/2 to the client.
func (sp ListenerSpec) http2Allowed() bool { return sp.HTTP2 == nil || *sp.HTTP2 }

// redirectFor answers where a request that named host:port should actually be sent. Both
// halves are independent, which is what lets a listener move every request to one test
// origin's port while leaving the hostname alone, and vice versa.
func (sp ListenerSpec) redirectFor(host string, port uint16) (string, uint16) {
	if sp.RedirectHost != "" {
		host = sp.RedirectHost
	}
	if sp.RedirectPort != 0 {
		port = sp.RedirectPort
	}
	return host, port
}

// redirects reports whether this listener moves requests at all.
func (sp ListenerSpec) redirects() bool { return sp.RedirectHost != "" || sp.RedirectPort != 0 }

// invisibleWith resolves the tri-state against the process-wide option.
func (sp ListenerSpec) invisibleWith(global bool) bool {
	if sp.Invisible != nil {
		return *sp.Invisible
	}
	return global
}

// ListenerStatus is one listener as the API reports it: the spec the operator set plus the
// address the accept loop is actually serving. BoundAddr differs from Bind whenever the
// operator asked for an ephemeral port, and is empty only for a listener whose socket has
// been closed — which, given RemoveListener drops the entry in the same breath, should not
// be observable.
type ListenerStatus struct {
	ListenerSpec
	BoundAddr string
}

// boundListener is a spec with the socket serving it. The mutex guards both, so a live
// update is a single atomic swap as far as the accept loop and the relay are concerned.
type boundListener struct {
	mu   sync.Mutex
	spec ListenerSpec
	ln   net.Listener
	// cert is the PKCS#12 bundle this listener serves, loaded once when the spec was validated
	// (burpsy-react-ui-4trc). Nil in every other mode, where the certificate is minted per
	// connection. Held here rather than re-read per handshake so a connection can never be the
	// thing that discovers the configuration is broken.
	cert   *tls.Certificate
	closed bool
}

func (b *boundListener) snapshot() (ListenerSpec, net.Listener) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.spec, b.ln
}

func (b *boundListener) current() net.Listener {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ln
}

func (b *boundListener) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// Listeners reports every listener the engine is serving, boot listener first and the rest
// in the order they were added. The slice is always non-nil: an empty collection has to
// reach the browser as [] and not null, because the console reads .length off it.
func (s *Server) Listeners() []ListenerStatus {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	out := make([]ListenerStatus, 0, len(s.listenerOrder))
	for _, id := range s.listenerOrder {
		bl := s.listeners[id]
		if bl == nil {
			continue
		}
		spec, ln := bl.snapshot()
		addr := ""
		if ln != nil {
			addr = ln.Addr().String()
		}
		out = append(out, ListenerStatus{ListenerSpec: spec, BoundAddr: addr})
	}
	return out
}

// ErrNotListening is what the mutating calls answer before ListenAndServe has started. A
// listener added to a server with no accept context would bind a socket nothing ever
// accepted on — the silently dead listener the bead refuses.
var ErrNotListening = errors.New("the proxy is not listening yet, so a listener cannot be added or changed")

// ErrNoSuchListener is what an id that names nothing answers.
var ErrNoSuchListener = errors.New("no listener with that id")

// ErrBootListenerNotRemovable is the removal policy, stated: the boot listener is the one
// -proxy-bind opened and the one the legacy single-listener surface (ListenerAddr, Rebind,
// the in-browser panel, cmd/burpsy's startup banner) answers about. It can be re-bound, so
// an operator is never stuck with the port they started on, but removing it would leave
// that surface describing nothing — and would let the collection become empty, which is the
// one state that turns the proxy into a process with no way in. Added listeners have no
// such role and can be removed at any time.
var ErrBootListenerNotRemovable = errors.New("the boot listener cannot be removed — re-bind it instead; only listeners added on this page can be removed")

// AddListener binds a new listener and starts serving it, answering the listener as it ended
// up (with its resolved address). A bind that fails is refused with the reason and nothing
// is added: there is no state in which the collection holds a listener that is not accepting.
func (s *Server) AddListener(spec ListenerSpec) (ListenerStatus, error) {
	s.rebindMu.Lock()
	defer s.rebindMu.Unlock()

	s.listenerMu.Lock()
	ctx := s.serveCtx
	s.listenerMu.Unlock()
	if ctx == nil {
		return ListenerStatus{}, ErrNotListening
	}
	if err := ctx.Err(); err != nil {
		return ListenerStatus{}, ErrNotListening
	}

	// The certificate selection is validated BEFORE the socket is opened (burpsy-react-ui-4trc): a
	// bundle that cannot be loaded must fail the edit, and failing after binding would leave a
	// listener accepting connections it cannot serve the configured certificate for.
	cert, err := validateCert(spec)
	if err != nil {
		return ListenerStatus{}, err
	}

	ln, err := net.Listen("tcp", spec.Bind)
	if err != nil {
		return ListenerStatus{}, fmt.Errorf("failed to bind proxy listener on %s: %w", spec.Bind, err)
	}

	s.listenerMu.Lock()
	s.listenerSeq++
	spec.ID = "listener-" + strconv.Itoa(s.listenerSeq)
	bl := &boundListener{spec: spec, ln: ln, cert: cert}
	s.listeners[spec.ID] = bl
	s.listenerOrder = append(s.listenerOrder, spec.ID)
	s.listenerMu.Unlock()

	s.config.logger.Info("proxy listener added",
		zap.String("id", spec.ID),
		zap.String("addr", ln.Addr().String()))

	go s.serveListener(ctx, bl)
	s.noteListenersChange()
	return ListenerStatus{ListenerSpec: spec, BoundAddr: ln.Addr().String()}, nil
}

// OnListenersChange installs the signal called after the listener table visibly moves: a
// listener added, removed, rebound, or updated to a spec that differs. Single slot, mirroring
// OnWsLiveChange; the hook runs synchronously on the edit's path.
func (s *Server) OnListenersChange(fn func()) {
	s.listenersChange.Store(fn)
}

// noteListenersChange invokes the installed hook, if any.
func (s *Server) noteListenersChange() {
	if fn, ok := s.listenersChange.Load().(func()); ok {
		fn()
	}
}

// listenerSpecEqual compares two specs by meaning, not pointer: the tri-state fields
// (Invisible, HTTP2) are equal when both are nil - "inherit" - or when both point at the same
// VALUE, so two separately decoded true pointers are the same setting. nil versus an explicit
// false is a real difference: inherit is not force-off.
func listenerSpecEqual(a, b ListenerSpec) bool {
	return a.Bind == b.Bind &&
		a.RedirectHost == b.RedirectHost &&
		a.RedirectPort == b.RedirectPort &&
		a.ForceTLS == b.ForceTLS &&
		triStateEqual(a.Invisible, b.Invisible) &&
		a.CertMode == b.CertMode &&
		a.CertHostname == b.CertHostname &&
		a.CertFile == b.CertFile &&
		a.CertPassword == b.CertPassword &&
		a.TLSMinVersion == b.TLSMinVersion &&
		a.TLSMaxVersion == b.TLSMaxVersion &&
		triStateEqual(a.HTTP2, b.HTTP2)
}

func triStateEqual(a, b *bool) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

// UpdateListener replaces a listener's spec. When the bind address changes the socket moves
// the way Rebind moves the boot listener's — the new socket is opened before the old one is
// closed, so a bind failure leaves the listener serving untouched and is an error the
// operator sees rather than an outage. The behaviour fields apply from the next connection
// this listener accepts; connections already being relayed keep the spec they started under.
func (s *Server) UpdateListener(id string, spec ListenerSpec) (ListenerStatus, error) {
	s.rebindMu.Lock()
	defer s.rebindMu.Unlock()

	s.listenerMu.Lock()
	bl := s.listeners[id]
	s.listenerMu.Unlock()
	if bl == nil {
		return ListenerStatus{}, ErrNoSuchListener
	}

	// Validated before any part of the edit lands, for the reason AddListener states: a listener
	// whose new bundle cannot be loaded keeps serving exactly what it served before, rather than
	// falling back to the process CA and looking like it worked.
	loadedCert, err := validateCert(spec)
	if err != nil {
		return ListenerStatus{}, err
	}

	bl.mu.Lock()
	current := bl.spec
	currentBind := bl.spec.Bind
	currentAddr := ""
	if bl.ln != nil {
		currentAddr = bl.ln.Addr().String()
	}
	bl.mu.Unlock()
	spec.ID = current.ID
	moved := !listenerSpecEqual(current, spec)

	// An unchanged bind must not re-open the socket: a spec-only edit (a redirect, a tick)
	// would otherwise drop the accept socket for an instant and, for an ephemeral bind,
	// come back on a different port than the one the operator is pointing a client at.
	//
	// The resolved address counts as unchanged too, and that is not a nicety: a listener
	// asked for 127.0.0.1:0 reports a bind of "127.0.0.1:0" and a bound address of the real
	// port, so an operator who types the port they can see would otherwise be trying to bind
	// a socket this very listener is holding — address-in-use, refused, for asking for the
	// state they are already in.
	if spec.Bind == currentBind || spec.Bind == currentAddr {
		bl.mu.Lock()
		bl.spec = spec
		bl.cert = loadedCert
		addr := currentAddr
		bl.mu.Unlock()
		s.config.logger.Info("proxy listener updated", zap.String("id", id), zap.String("addr", addr))
		if moved {
			s.noteListenersChange()
		}
		return ListenerStatus{ListenerSpec: spec, BoundAddr: addr}, nil
	}

	ln, err := net.Listen("tcp", spec.Bind)
	if err != nil {
		return ListenerStatus{}, fmt.Errorf("failed to bind proxy listener on %s: %w", spec.Bind, err)
	}
	bl.mu.Lock()
	old := bl.ln
	bl.ln = ln
	bl.spec = spec
	// The rebinding path swaps the bundle with the spec for the same reason the in-place path
	// does: an edit that changed BOTH the bind address and the certificate would otherwise move
	// the socket and keep serving the old bundle.
	bl.cert = loadedCert
	bl.mu.Unlock()
	if old != nil {
		old.Close()
	}
	s.config.logger.Info("proxy listener rebound",
		zap.String("id", id),
		zap.String("addr", ln.Addr().String()),
		zap.String("previous", currentAddr))
	s.noteListenersChange()
	return ListenerStatus{ListenerSpec: spec, BoundAddr: ln.Addr().String()}, nil
}

// RemoveListener closes a listener's socket and drops it from the collection.
//
// The policy, stated because "what happens to traffic on a listener being removed" is not a
// question an operator should have to discover: the socket stops accepting immediately, so
// no new client can reach the proxy through it, and connections it is already relaying are
// NOT disturbed — they run to completion on the sockets they already hold. That is the same
// contract Rebind has had since -77m, and it is why removing a listener that is busy is
// safe rather than merely tolerated. The boot listener is refused; see
// ErrBootListenerNotRemovable.
func (s *Server) RemoveListener(id string) error {
	s.rebindMu.Lock()
	defer s.rebindMu.Unlock()

	if id == bootListenerID {
		return ErrBootListenerNotRemovable
	}
	s.listenerMu.Lock()
	bl := s.listeners[id]
	if bl == nil {
		s.listenerMu.Unlock()
		return ErrNoSuchListener
	}
	delete(s.listeners, id)
	for i, known := range s.listenerOrder {
		if known == id {
			s.listenerOrder = append(s.listenerOrder[:i], s.listenerOrder[i+1:]...)
			break
		}
	}
	s.listenerMu.Unlock()

	bl.mu.Lock()
	bl.closed = true
	ln := bl.ln
	bl.ln = nil
	bl.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	s.config.logger.Info("proxy listener removed", zap.String("id", id))
	s.noteListenersChange()
	return nil
}

// serveListener is the accept loop for one listener. It is the loop ListenAndServe has
// always run, with the socket re-read per iteration so a re-bind is a handover rather than a
// death, and with the listener's own spec handed to every connection it accepts.
func (s *Server) serveListener(ctx context.Context, bl *boundListener) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		spec, ln := bl.snapshot()
		if ln == nil {
			return
		}
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if bl.isClosed() {
				return
			}
			// The socket was replaced under us by an Update — the previous one's Accept
			// errors immediately, which reads as a failure but is in fact the handover.
			if bl.current() != ln {
				continue
			}
			s.config.logger.Warn("accept failed", zap.String("id", spec.ID), zap.Error(err))
			continue
		}

		// The spec is re-read here rather than used as snapshotted above, because Accept
		// blocks: the value read before it was the listener's configuration at the time the
		// loop last went round, which for an idle listener is before any edit the operator
		// has made since. Relaying under it made every per-listener setting one connection
		// late — a redirect set and then exercised went to the origin it had just been
		// pointed away from, and the identical second request did not. A connection is
		// relayed under the settings in force when it arrived; ones already being relayed
		// keep the spec they started under, which is what UpdateListener's comment promises.
		spec, _ = bl.snapshot()

		go s.handleConnectionOn(conn, spec)
	}
}

// normalizeRedirectHost validates Burp's "Redirect to host" value. A host with a scheme, a
// path or an embedded port is refused rather than quietly reinterpreted: ":port" is the
// other field, and a value this engine would dial as a hostname containing "/" can only be
// a mistake the operator wants told about now rather than as a failed relay later.
// NormalizeRedirectHost is exported because the API layer validates the operator's value
// before it ever reaches a spec — a redirect host is refused at the edge with the reason,
// not repaired silently on the way to a dial.
func NormalizeRedirectHost(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	if host == "" {
		return "", nil
	}
	if strings.Contains(host, "://") {
		return "", errors.New("redirect host is a hostname or IP, not a URL — drop the scheme")
	}
	if strings.ContainsAny(host, "/?# ") {
		return "", errors.New("redirect host is a hostname or IP: no path, query or spaces")
	}
	// A bracketed IPv6 literal is how one is written in an address, and is accepted; a bare
	// "host:port" is not, because the port belongs in the redirect-port field and silently
	// taking it from here would leave that field describing something untrue.
	if strings.HasPrefix(host, "[") {
		if !strings.HasSuffix(host, "]") {
			return "", errors.New("an IPv6 redirect host must be bracketed, as [::1]")
		}
		return host, nil
	}
	if strings.Count(host, ":") == 1 {
		return "", errors.New("redirect host carries a port — put the port in the redirect-port field instead")
	}
	if strings.Contains(host, ":") {
		// An unbracketed IPv6 literal. Bracket it so JoinHostPort and net.Dial agree.
		return "[" + host + "]", nil
	}
	return host, nil
}

// listenerCert returns the PKCS#12 bundle loaded for one listener, or nil when it has none —
// which is every mode except CertModePKCS12, and every connection arriving on the boot listener.
//
// Looked up by id at handshake time rather than threaded through handleConnectionOn and
// handleConnect, because those two carry a spec by VALUE: a listener edited between accept and
// handshake would otherwise hand the connection a bundle that no longer matches its own spec.
func (s *Server) listenerCert(id string) *tls.Certificate {
	if id == "" {
		return nil
	}
	s.listenerMu.Lock()
	bl := s.listeners[id]
	s.listenerMu.Unlock()
	if bl == nil {
		return nil
	}
	bl.mu.Lock()
	defer bl.mu.Unlock()
	return bl.cert
}
