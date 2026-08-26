package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/sender"
)

// ---- Repeater under the redirect policy ---------------------------------------------------------
//
// The network settings' redirect policy is only real if something obeys it. A settings surface whose
// value nothing reads is the defect this project has already had once — match & replace rules an
// operator edited were a live-traffic no-op because the proxy's rule set was never wired — so these
// tests assert the wiring rather than the struct: requests arriving at a second listener, or not.
//
// Repeater is the right consumer because that is where Burp puts "Follow redirections", and because its
// first send is the operator's own bytes: the hops are the only requests here that a Location chose, and
// they are the ones that go through sender.AuthorisedSender.

// redirectTarget is a test origin that 302s /go to location and answers /landed with a 200.
func redirectTarget(t *testing.T, location func() string) (*httptest.Server, func() []string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		if r.URL.Path == "/go" {
			w.Header().Set("Location", location())
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Write([]byte("landed"))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { return seen }
}

func repeaterSend(t *testing.T, s *Server, host string, port uint16, path string) map[string]any {
	t.Helper()
	authority := fmt.Sprintf("%s:%d", host, port)
	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target":  authority,
		"request": "GET " + path + " HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("repeater send = %d (%s)", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out
}

func setRedirectMode(t *testing.T, s *Server, mode string) {
	t.Helper()
	rec := putNetworkSettings(t, s, fmt.Sprintf(`{"redirects": {"mode": %q}}`, mode))
	if rec.Code != http.StatusOK {
		t.Fatalf("set redirect mode %s = %d (%s)", mode, rec.Code, rec.Body.String())
	}
}

func includeInScope(t *testing.T, s *Server, host string) {
	t.Helper()
	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "include", "pattern": host}); rec.Code != http.StatusOK {
		t.Fatalf("include %s: %d", host, rec.Code)
	}
}

// The default. One click is one request, and the answer says the policy is why — not that there was
// nothing to follow.
func TestRepeaterUnderTheDefaultPolicySendsOneRequestAndSaysWhy(t *testing.T) {
	srv, seen := redirectTarget(t, func() string { return "/landed" })
	host, port := targetHostPort(t, srv.URL)

	s := newTestServer()
	includeInScope(t, s, host)

	got := repeaterSend(t, s, host, port, "/go")
	if status, _ := got["status"].(float64); int(status) != http.StatusFound {
		t.Errorf("status = %v, want the 302 itself", got["status"])
	}
	block, ok := got["redirects"].(map[string]any)
	if !ok {
		t.Fatalf("no redirects block on a 302 response; the operator cannot tell the policy declined "+
			"to follow from the tool not having looked. body: %v", got)
	}
	if mode, _ := block["mode"].(string); mode != "never" {
		t.Errorf("mode = %v, want never", block["mode"])
	}
	if sent, _ := block["sent"].(float64); int(sent) != 1 {
		t.Errorf("sent = %v, want 1: the default follows nothing", block["sent"])
	}
	if complete, _ := block["complete"].(bool); complete {
		t.Error("complete = true on a chain that was still redirecting")
	}
	// The claim about the wire, not about the struct.
	if arrived := seen(); len(arrived) != 1 || arrived[0] != "/go" {
		t.Errorf("the target saw %v, want only /go", arrived)
	}
}

// The policy turned on actually follows, and the hop reaches the origin. Without this the refusal test
// below would pass on an implementation that followed nothing at all.
func TestRepeaterFollowsAHopWhenThePolicyIsOn(t *testing.T) {
	srv, seen := redirectTarget(t, func() string { return "/landed" })
	host, port := targetHostPort(t, srv.URL)

	s := newTestServer()
	includeInScope(t, s, host)
	setRedirectMode(t, s, "on_site")

	got := repeaterSend(t, s, host, port, "/go")
	block, ok := got["redirects"].(map[string]any)
	if !ok {
		t.Fatalf("no redirects block: %v", got)
	}
	if sent, _ := block["sent"].(float64); int(sent) != 2 {
		t.Errorf("sent = %v, want 2", block["sent"])
	}
	if complete, _ := block["complete"].(bool); !complete {
		t.Errorf("complete = false on a chain that reached a 200: %v", block)
	}
	if final, _ := block["final_status"].(float64); int(final) != http.StatusOK {
		t.Errorf("final_status = %v, want 200", block["final_status"])
	}
	// `response` stays the response to the bytes the operator wrote — the 302 with its headers — which
	// is Repeater's contract and the reason the chain is reported alongside rather than substituted.
	if status, _ := got["status"].(float64); int(status) != http.StatusFound {
		t.Errorf("status = %v; the operator's own request answered with a 302 and that must not be "+
			"replaced by a later hop's", got["status"])
	}
	if arrived := seen(); len(arrived) != 2 || arrived[1] != "/landed" {
		t.Fatalf("the target saw %v, want /go then /landed", arrived)
	}
}

// The security property, through the whole stack: a hop the scope refuses does not reach a socket, even
// under the most permissive mode the settings offer.
func TestRepeaterRefusesAnOutOfScopeRedirectHop(t *testing.T) {
	var reached []string
	guarded := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = append(reached, r.URL.Path)
		w.Write([]byte("should never be reached"))
	}))
	defer guarded.Close()
	guardedHost, guardedPort := targetHostPort(t, guarded.URL)

	srv, seen := redirectTarget(t, func() string {
		return fmt.Sprintf("http://%s:%d/secret", guardedHost, guardedPort)
	})
	host, port := targetHostPort(t, srv.URL)

	s := newTestServer()
	// Only the first authority is in scope. Both listeners are on the same host, so the rule that keeps
	// them apart is a port rule — which is the shape of a Location aimed at a neighbouring service.
	if rec := postJSON(t, s, "/api/scope", map[string]any{
		"action": "include", "pattern": host, "port": port,
	}); rec.Code != http.StatusOK {
		t.Fatalf("include %s:%d: %d (%s)", host, port, rec.Code, rec.Body.String())
	}
	// The most permissive mode, deliberately: "always" must mean "no extra filter of my own", never
	// "send what the scope forbids".
	setRedirectMode(t, s, "always")

	got := repeaterSend(t, s, host, port, "/go")
	block, ok := got["redirects"].(map[string]any)
	if !ok {
		t.Fatalf("no redirects block: %v", got)
	}
	if sent, _ := block["sent"].(float64); int(sent) != 1 {
		t.Errorf("sent = %v, want 1: only the operator's own request was authorised", block["sent"])
	}
	if complete, _ := block["complete"].(bool); complete {
		t.Error("complete = true on a chain the scope stopped")
	}
	hops, _ := block["hops"].([]any)
	if len(hops) != 1 {
		t.Fatalf("hops = %v, want one", block["hops"])
	}
	hop, _ := hops[0].(map[string]any)
	if followed, _ := hop["followed"].(bool); followed {
		t.Error("the out-of-scope hop is recorded as followed")
	}
	if reason, _ := hop["reason"].(string); reason == "" {
		t.Error("the refused hop carries no reason")
	}
	// The assertion that actually matters.
	if len(reached) != 0 {
		t.Fatalf("the out-of-scope authority received %v; a redirect hop escaped the scope check", reached)
	}
	if arrived := seen(); len(arrived) != 1 {
		t.Errorf("the in-scope target saw %v, want only /go", arrived)
	}
}

// A response that is not a redirect gets no block at all, so a client can read the field's presence as
// "there was a chain here" rather than having to inspect an empty one.
func TestRepeaterReportsNoRedirectBlockForAnOrdinaryResponse(t *testing.T) {
	srv, _ := redirectTarget(t, func() string { return "/landed" })
	host, port := targetHostPort(t, srv.URL)

	s := newTestServer()
	includeInScope(t, s, host)
	setRedirectMode(t, s, "in_scope")

	got := repeaterSend(t, s, host, port, "/landed")
	if _, present := got["redirects"]; present {
		t.Errorf("a 200 carries a redirects block: %v", got["redirects"])
	}
}

// The follower is reachable from the settings the endpoint writes, which is the join this whole unit is
// about: the mode the API accepted is the mode the repeater obeys, read off the same sender.
func TestTheRepeaterObeysTheModeTheEndpointAccepted(t *testing.T) {
	s := newTestServer()
	for _, mode := range []sender.RedirectMode{
		sender.RedirectNever, sender.RedirectOnSite, sender.RedirectInScope, sender.RedirectAlways,
	} {
		setRedirectMode(t, s, string(mode))
		if got := s.sender.Network().Redirects.Mode; got != mode {
			t.Errorf("the sender the repeater reads is in mode %q after the endpoint accepted %q", got, mode)
		}
	}
}
