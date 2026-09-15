package proxy

import (
	"context"
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
}

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
	mu     sync.Mutex
	spec   ListenerSpec
	ln     net.Listener
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

	ln, err := net.Listen("tcp", spec.Bind)
	if err != nil {
		return ListenerStatus{}, fmt.Errorf("failed to bind proxy listener on %s: %w", spec.Bind, err)
	}

	s.listenerMu.Lock()
	s.listenerSeq++
	spec.ID = "listener-" + strconv.Itoa(s.listenerSeq)
	bl := &boundListener{spec: spec, ln: ln}
	s.listeners[spec.ID] = bl
	s.listenerOrder = append(s.listenerOrder, spec.ID)
	s.listenerMu.Unlock()

	s.config.logger.Info("proxy listener added",
		zap.String("id", spec.ID),
		zap.String("addr", ln.Addr().String()))

	go s.serveListener(ctx, bl)
	return ListenerStatus{ListenerSpec: spec, BoundAddr: ln.Addr().String()}, nil
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

	spec.ID = id
	bl.mu.Lock()
	currentBind := bl.spec.Bind
	currentAddr := ""
	if bl.ln != nil {
		currentAddr = bl.ln.Addr().String()
	}
	bl.mu.Unlock()

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
		addr := currentAddr
		bl.mu.Unlock()
		s.config.logger.Info("proxy listener updated", zap.String("id", id), zap.String("addr", addr))
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
	bl.mu.Unlock()
	if old != nil {
		old.Close()
	}
	s.config.logger.Info("proxy listener rebound",
		zap.String("id", id),
		zap.String("addr", ln.Addr().String()),
		zap.String("previous", currentAddr))
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
