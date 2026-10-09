package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/oob"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// The Collaborator health check and "Don't use Collaborator" (burpsy-react-ui-8e3n), through the real
// routes. The network is replaced by probes that record an interaction on a fake channel, the way the
// interaction server would, so the whole decision path runs: which items connected, which interactions
// came back, and what the overall status says about trusting an out-of-band check.

// healthChannel is an OOB channel whose interaction log the fake probes append to.
type healthChannel struct {
	domain string
	mu     sync.Mutex
	log    []oob.Interaction
}

func (c *healthChannel) Domain() string { return c.domain }

func (c *healthChannel) InteractionsFor(marker string) ([]oob.Interaction, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []oob.Interaction{}
	for _, in := range c.log {
		if marker == "" || strings.Contains(in.RawRequest, marker) {
			out = append(out, in)
		}
	}
	return out, nil
}

func (c *healthChannel) record(protocol, raw string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log = append(c.log, oob.Interaction{Protocol: protocol, RawRequest: raw, Timestamp: time.Now()})
}

// healthProvider is a provider with an open channel, and remembers whether it was closed.
type healthProvider struct {
	ch      *healthChannel
	openErr error
	closed  bool
}

func (p *healthProvider) Channel(context.Context) (scanner.OOBChannel, error) {
	if p.openErr != nil {
		return nil, p.openErr
	}
	return p.ch, nil
}

func (p *healthProvider) Registration() scanner.OOBRegistration {
	if p.openErr != nil {
		return scanner.OOBRegistration{Attempted: true, Err: p.openErr}
	}
	return scanner.OOBRegistration{Attempted: true, Open: true, Domain: p.ch.domain, Server: "https://oast.example"}
}

func (p *healthProvider) Close() error { p.closed = true; return nil }

// probeWorld says which connection items succeed; a success records the interaction the server would
// see. DNS is recorded with the marker upper-cased, which is what DNS-0x20 does to a raw DNS request.
type probeWorld struct {
	dns, http, httpsTrusted, https, smtp25, smtp587, smtps bool
	dropHTTP                                               bool // the server never reports HTTP
}

func (w probeWorld) probes(ch *healthChannel) *collaboratorProbes {
	refused := errors.New("connection refused")
	return &collaboratorProbes{
		resolve: func(_ context.Context, host string) error {
			if !w.dns {
				return errors.New("no such host")
			}
			ch.record("dns", ";; QUESTION SECTION:\n;"+strings.ToUpper(host)+".\tIN\tA")
			return nil
		},
		httpGet: func(_ context.Context, url string, verify bool) error {
			ok := w.http
			if strings.HasPrefix(url, "https://") {
				ok = w.https && (w.httpsTrusted || !verify)
			}
			if !ok {
				return refused
			}
			if !w.dropHTTP {
				ch.record("http", "GET / HTTP/1.1\r\nHost: "+strings.TrimSuffix(strings.SplitN(url, "://", 2)[1], "/"))
			}
			return nil
		},
		smtp: func(_ context.Context, host string, port int, _, _ bool, marker string) error {
			ok := (port == 25 && w.smtp25) || (port == 587 && w.smtp587) || (port == 465 && w.smtps)
			if !ok {
				return refused
			}
			ch.record("smtp", "RCPT TO:<"+marker+"@"+host+">")
			return nil
		},
	}
}

type healthReply struct {
	Status      string `json:"status"`
	Summary     string `json:"summary"`
	Address     string `json:"address"`
	Connections []struct {
		Name      string `json:"name"`
		Status    string `json:"status"`
		LatencyMS *int64 `json:"latency_ms"`
	} `json:"connections"`
	Captures []struct {
		Protocol string `json:"protocol"`
		Status   string `json:"status"`
		Detail   string `json:"detail"`
	} `json:"captures"`
}

func runHealth(t *testing.T, world probeWorld) (healthReply, string) {
	t.Helper()
	s := newTestServerWithScanner(t)
	ch := &healthChannel{domain: "abc123.oast.example"}
	s.wiredScanner().WithOOBProvider(&healthProvider{ch: ch})
	hub := s.collab()
	hub.healthProbes = world.probes(ch)
	hub.healthWait = 300 * time.Millisecond
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/collaborator/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/collaborator/health = %d: %s", rec.Code, rec.Body.String())
	}
	var out healthReply
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out, rec.Body.String()
}

func captureStatus(r healthReply) map[string]string {
	out := map[string]string{}
	for _, c := range r.Captures {
		out[c.Protocol] = c.Status
	}
	return out
}

func Test_health_check_runs_burps_eight_items_and_is_healthy_when_every_protocol_comes_back(t *testing.T) {
	r, raw := runHealth(t, probeWorld{dns: true, http: true, https: true, httpsTrusted: false, smtp25: false, smtp587: true})
	want := []string{
		"Server address resolution", "Server HTTP connection",
		"Server HTTPS connection (trust enforced)", "Server HTTPS connection (trust not enforced)",
		"Server SMTP connection on port 25", "Server SMTP connection on port 587",
		"Server SMTPS connection (trust enforced)", "Server SMTPS connection (trust not enforced)",
	}
	if len(r.Connections) != len(want) {
		t.Fatalf("%d connection items, want %d: %s", len(r.Connections), len(want), raw)
	}
	wantOK := []bool{true, true, false, true, false, true, false, false}
	for i, c := range r.Connections {
		if c.Name != want[i] {
			t.Errorf("item %d = %q, want %q (Burp's order)", i, c.Name, want[i])
		}
		if (c.Status == healthOK) != wantOK[i] {
			t.Errorf("%s: status %s, want ok=%v", c.Name, c.Status, wantOK[i])
		}
		if (c.LatencyMS != nil) != wantOK[i] {
			t.Errorf("%s: latency %v — a failed item has no latency, and must marshal null", c.Name, c.LatencyMS)
		}
	}
	if !strings.Contains(raw, `"latency_ms":null`) {
		t.Error("a failed item's latency did not marshal as null")
	}
	if got := captureStatus(r); got["dns"] != healthOK || got["http"] != healthOK || got["smtp"] != healthOK {
		t.Errorf("captures %v, want all ok — the DNS row arrives upper-cased (DNS-0x20) and must still match", got)
	}
	if r.Status != "healthy" || !strings.HasSuffix(r.Address, ".abc123.oast.example") {
		t.Errorf("status %q address %q", r.Status, r.Address)
	}
}

// A protocol whose triggers all failed is not_triggered, which names this machine's egress as the cause.
// "not captured" would blame the server for something that was never sent.
func Test_health_check_separates_not_triggered_from_not_captured(t *testing.T) {
	r, _ := runHealth(t, probeWorld{dns: true, http: true, https: true, httpsTrusted: true, dropHTTP: true})
	got := captureStatus(r)
	if got["smtp"] != healthNotTriggered {
		t.Errorf("smtp capture %q, want not_triggered: no SMTP item connected", got["smtp"])
	}
	if got["http"] != healthError {
		t.Errorf("http capture %q, want error: the trigger went out and nothing came back", got["http"])
	}
	if got["dns"] != healthOK || r.Status != "degraded" {
		t.Errorf("dns %q status %q, want ok / degraded", got["dns"], r.Status)
	}
	if !strings.Contains(r.Summary, "HTTP and SMTP") {
		t.Errorf("summary %q does not name what is missing", r.Summary)
	}
}

func Test_health_check_fails_when_nothing_comes_back(t *testing.T) {
	r, _ := runHealth(t, probeWorld{})
	if r.Status != "failed" {
		t.Errorf("status %q, want failed", r.Status)
	}
	for _, c := range r.Captures {
		if c.Status != healthNotTriggered {
			t.Errorf("%s capture %q, want not_triggered", c.Protocol, c.Status)
		}
	}
}

func Test_health_check_refuses_without_a_channel(t *testing.T) {
	s := newTestServerWithScanner(t)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/collaborator/health", nil))
	if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), `"captures"`) {
		t.Errorf("unconfigured: %d %s, want 409 and no report", rec.Code, rec.Body.String())
	}
	s.wiredScanner().WithOOBProvider(&healthProvider{openErr: errors.New("interactsh-client not found")})
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/collaborator/health", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "interactsh-client not found") {
		t.Errorf("broken channel: %d %s, want 503 naming the cause", rec.Code, rec.Body.String())
	}
}

func deleteCollaboratorServer(s *Server, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/collaborator/server", strings.NewReader(body)))
	return rec
}

// "Don't use Collaborator": an open channel is closed only on purpose, and afterwards the installation
// refuses to mint, as if it had never been configured.
func Test_unsetting_the_collaborator_server(t *testing.T) {
	s := newTestServerWithScanner(t)
	p := &healthProvider{ch: &healthChannel{domain: "abc123.oast.example"}}
	s.wiredScanner().WithOOBProvider(p)
	hub := s.collab()
	hub.minted = []mintedPayload{{Address: "a.abc123.oast.example", Marker: "a"}, {Address: "b.abc123.oast.example", Marker: "b"}}

	rec := deleteCollaboratorServer(s, "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "abc123.oast.example") ||
		!strings.Contains(rec.Body.String(), `"minted_payload":2`) || p.closed {
		t.Fatalf("open channel, no confirmation: %d %s closed=%v, want 409 naming the domain and 2 payloads, not closed",
			rec.Code, rec.Body.String(), p.closed)
	}

	rec = deleteCollaboratorServer(s, `{"discard_open_channel":true}`)
	if rec.Code != http.StatusOK || !p.closed {
		t.Fatalf("confirmed: %d %s closed=%v", rec.Code, rec.Body.String(), p.closed)
	}
	var out struct {
		Orphaned     int    `json:"orphaned_payloads"`
		ClosedDomain string `json:"closed_domain"`
		Status       struct {
			Configured bool            `json:"configured"`
			State      string          `json:"state"`
			Payloads   json.RawMessage `json:"payloads"`
		} `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Orphaned != 2 || out.ClosedDomain != "abc123.oast.example" || out.Status.Configured ||
		out.Status.State != collabNotConfigured || string(out.Status.Payloads) != "[]" {
		t.Errorf("after unset: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/collaborator/payload", nil))
	if rec.Code != http.StatusConflict {
		t.Errorf("mint after unset = %d, want 409: an unset channel must refuse, never hand out an address", rec.Code)
	}

	// Configuring a server again must not resurrect the old payloads. They belong to the closed domain, so
	// listing them under the new channel would show interactions nobody can see as "none yet".
	s.wiredScanner().WithOOBProvider(&healthProvider{ch: &healthChannel{domain: "fresh99.other.example"}})
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/collaborator/status", nil))
	if !strings.Contains(rec.Body.String(), `"payloads":[]`) || strings.Contains(rec.Body.String(), "abc123") {
		t.Errorf("a new channel after unset lists the closed domain's payloads: %s", rec.Body.String())
	}
	s.wiredScanner().ClearOOBProvider(false)

	// Idempotent: unsetting nothing is not an error.
	if rec := deleteCollaboratorServer(s, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"was_configured":false`) {
		t.Errorf("second unset: %d %s", rec.Code, rec.Body.String())
	}
}

// Burp's CSV export carries each interaction's bytes as Base64 (aw2y). ?full=1 adds them to the rows;
// the table's polling read leaves them off.
func Test_interaction_rows_carry_base64_bytes_only_when_asked(t *testing.T) {
	s := newTestServerWithScanner(t)
	ch := &healthChannel{domain: "abc123.oast.example"}
	ch.log = []oob.Interaction{{Protocol: "http", RawRequest: "GET /x HTTP/1.1\r\n", RawResponse: "HTTP/1.1 200 OK\r\n"}}
	s.wiredScanner().WithOOBProvider(&healthProvider{ch: ch})
	get := func(q string) string {
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/collaborator/interactions"+q, nil))
		return rec.Body.String()
	}
	if plain := get(""); strings.Contains(plain, "raw_request_b64") {
		t.Errorf("the polling read carries bytes: %s", plain)
	}
	full := get("?full=1")
	if !strings.Contains(full, `"raw_request_b64":"R0VUIC94IEhUVFAvMS4xDQo="`) ||
		!strings.Contains(full, `"raw_response_b64":"SFRUUC8xLjEgMjAwIE9LDQo="`) {
		t.Errorf("?full=1 rows lack the Base64 bytes: %s", full)
	}
}
