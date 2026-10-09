package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// ---- project switch and network authentication (burpsy-react-ui-oava) -----------------------
//
// The recorded-login library was replaced on a switch; the platform-authentication rules and the
// client-certificate bindings were not, so project A's password and client identity stayed on the
// panel AND on the wire under project B. These tests look at both: what the API lists, and what a
// real TLS target actually receives from the sender the stores are shared with.

// presented is what one request delivered to the target: an Authorization header, a client
// certificate on the TLS connection it rode.
type presented struct {
	authorization bool
	certificate   bool
}

// clientAuthTarget is a TLS server that asks for (but does not require) a client certificate and
// records what each request carried. Keep-alive stays on, so a pooled connection that completed its
// handshake under an earlier binding shows up here as a certificate that should not be there.
func clientAuthTarget(t *testing.T) (*httptest.Server, func() presented) {
	t.Helper()
	var mu sync.Mutex
	var last presented
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = presented{
			authorization: r.Header.Get("Authorization") != "",
			certificate:   r.TLS != nil && len(r.TLS.PeerCertificates) > 0,
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, func() presented {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

// sendThrough sends one GET to target through snd and returns what the target saw.
func sendThrough(t *testing.T, snd *sender.Sender, target string, seen func() presented) presented {
	t.Helper()
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := snd.Send(context.Background(), &sender.Request{
		Method: http.MethodGet, URL: target + "/", Host: parsed.Hostname(), Path: "/", Port: uint16(port), TLS: true,
	})
	if err != nil {
		t.Fatalf("sending to the target: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the target answered %d", resp.StatusCode)
	}
	return seen()
}

// netAuthListed reads both panels and returns how many rules and bindings each lists.
func netAuthListed(t *testing.T, srv *Server) (rules, bindings int) {
	t.Helper()
	var auth platformAuthResponse
	if err := json.Unmarshal(call(t, srv, http.MethodGet, "/api/network/auth", "").Body.Bytes(), &auth); err != nil {
		t.Fatalf("decoding /api/network/auth: %v", err)
	}
	var certs clientCertsResponse
	if err := json.Unmarshal(call(t, srv, http.MethodGet, "/api/network/client-certs", "").Body.Bytes(), &certs); err != nil {
		t.Fatalf("decoding /api/network/client-certs: %v", err)
	}
	if auth.Empty != (len(auth.Rules) == 0) || certs.Empty != (len(certs.Bindings) == 0) {
		t.Fatalf("empty flags disagree with the lists: auth %+v certs %+v", auth, certs)
	}
	return len(auth.Rules), len(certs.Bindings)
}

func TestSwitchingProjectsReplacesNetworkAuthenticationOnThePanelAndOnTheWire(t *testing.T) {
	target, seen := clientAuthTarget(t)
	host := "127.0.0.1"

	dir := t.TempDir()
	projectA, err := persist.Open(filepath.Join(dir, "a.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	// Project B exists and has never configured network authentication.
	projectB, err := persist.Open(filepath.Join(dir, "b.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := projectB.Close(); err != nil {
		t.Fatal(err)
	}

	// Wired the way cmd/burpsy wires it: one pair of stores, shared by the API and the sender.
	credentials, certs := netauth.NewCredentials(), netauth.NewClientCerts()
	config := sender.DefaultSenderConfig()
	config.PlatformAuth = credentials
	config.ClientCerts = certs
	config.TLSVerify = false
	snd := sender.NewSender(config)
	srv := newTestServer().WithSender(snd).WithNetAuth(credentials, certs).WithPersist(projectA)
	t.Cleanup(srv.CloseProject)

	// Project A configures a Basic credential and a client certificate for the target.
	if rec := call(t, srv, http.MethodPost, "/api/network/auth",
		`{"host":"`+host+`","scheme":"basic","username":"alice","password":"`+apiPassword+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("adding the credential = %d: %s", rec.Code, rec.Body.String())
	}
	p12 := writeTestP12(t, apiPassphrase)
	if rec := call(t, srv, http.MethodPost, "/api/network/client-certs",
		`{"host":"`+host+`","path":`+jsonString(p12)+`,"passphrase":"`+apiPassphrase+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("binding the certificate = %d: %s", rec.Code, rec.Body.String())
	}
	if rules, bindings := netAuthListed(t, srv); rules != 1 || bindings != 1 {
		t.Fatalf("project A lists %d rules and %d bindings, want 1 and 1", rules, bindings)
	}
	// Positive control: under A, both reach the target. Without this, the assertions after the
	// switch would pass for a sender that never presented anything.
	if got := sendThrough(t, snd, target.URL, seen); !got.authorization || !got.certificate {
		t.Fatalf("under project A the target saw %+v, want both the credential and the certificate", got)
	}

	// Switch to B.
	if rec := openProjectSwitch(t, srv, filepath.Join(dir, "b.db")); rec.Code != http.StatusOK {
		t.Fatalf("switching to B = %d: %s", rec.Code, rec.Body.String())
	}
	if rules, bindings := netAuthListed(t, srv); rules != 0 || bindings != 0 {
		t.Fatalf("after switching to B the panel lists %d rules and %d bindings from project A, want none", rules, bindings)
	}
	// And the wire: no Authorization header, and no certificate — including on a connection the
	// sender kept open from A's send, which completed its handshake presenting A's identity.
	if got := sendThrough(t, snd, target.URL, seen); got.authorization || got.certificate {
		t.Fatalf("after switching to B the target still received project A's network authentication: %+v", got)
	}
	// B's file holds nothing of A's: a save in B mirrors the whole in-memory list, so a store that
	// kept A's rules would have written them here on the next edit.
	if rows, err := srv.persist.LoadPlatformAuth(); err != nil || len(rows) != 0 {
		t.Fatalf("project B's file holds %d platform-auth rows (err %v), want 0", len(rows), err)
	}
	if rows, err := srv.persist.LoadClientCerts(); err != nil || len(rows) != 0 {
		t.Fatalf("project B's file holds %d client-cert rows (err %v), want 0", len(rows), err)
	}

	// Back to A: A persisted both, so both come back, on the panel and on the wire.
	if rec := openProjectSwitch(t, srv, filepath.Join(dir, "a.db")); rec.Code != http.StatusOK {
		t.Fatalf("switching back to A = %d: %s", rec.Code, rec.Body.String())
	}
	if rules, bindings := netAuthListed(t, srv); rules != 1 || bindings != 1 {
		t.Fatalf("back in project A the panel lists %d rules and %d bindings, want A's 1 and 1", rules, bindings)
	}
	if got := sendThrough(t, snd, target.URL, seen); !got.authorization || !got.certificate {
		t.Fatalf("back in project A the target saw %+v, want both restored", got)
	}
}

// A binding that cannot be rebuilt in the incoming project is reported for THAT project, and the
// outgoing project's restore failures do not linger on the panel after a switch.
func TestASwitchReportsTheIncomingProjectsRestoreFailures(t *testing.T) {
	dir := t.TempDir()
	projectA, err := persist.Open(filepath.Join(dir, "a.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := persist.Open(filepath.Join(dir, "b.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	projectB.SaveClientCerts([]netauth.ClientCertRow{{Host: "b.example", Path: filepath.Join(dir, "gone.p12"), Passphrase: "x"}})
	if err := projectB.Close(); err != nil {
		t.Fatal(err)
	}

	srv := newTestServer().WithNetAuth(netauth.NewCredentials(), netauth.NewClientCerts()).
		WithNetAuthRestoreNotes([]string{"a note from project A's startup restore"}).WithPersist(projectA)
	t.Cleanup(srv.CloseProject)

	if rec := openProjectSwitch(t, srv, filepath.Join(dir, "b.db")); rec.Code != http.StatusOK {
		t.Fatalf("switching to B = %d: %s", rec.Code, rec.Body.String())
	}
	var certs clientCertsResponse
	if err := json.Unmarshal(call(t, srv, http.MethodGet, "/api/network/client-certs", "").Body.Bytes(), &certs); err != nil {
		t.Fatal(err)
	}
	if len(certs.RestoreFailures) != 1 || certs.RestoreFailures[0] == "a note from project A's startup restore" {
		t.Fatalf("after switching to B the panel reports %q, want exactly B's one unrestorable binding", certs.RestoreFailures)
	}
	if !certs.Empty {
		t.Fatalf("a binding whose file is gone was listed as bound: %+v", certs.Bindings)
	}
}
