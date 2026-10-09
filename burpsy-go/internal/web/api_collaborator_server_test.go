package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/oob"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// newTestServerWithScanner attaches a real ActiveScanner, because the endpoint under test installs
// a provider onto one and the assertions read it back off the same handle.
func newTestServerWithScanner(t *testing.T) *Server {
	t.Helper()
	return newTestServer().WithScanner(
		scanner.NewActiveScanner(core.NewTrafficStore(), zap.NewNop()))
}

// ---- POST /api/collaborator/server (W6 #6) --------------------------------------------------
//
// The Collaborator capability was real and completely unreachable from the console:
// -collaborator-server is read once at startup, so an operator who forgot it had 26 corpus checks
// gated off for the rest of the session with a restart as the only remedy — and a restart costs
// them their captured traffic.
//
// The interesting tests here are the refusals. A setter that quietly accepted a change after a
// channel had registered would detach the operator from their own evidence: minted addresses belong
// to the old domain, findings reference those addresses, and nobody would be polling the server that
// could see the callbacks. This surface exists to distinguish "nothing called back" from "nobody was
// listening", and that is exactly the distinction such a swap would destroy.

func postCollaboratorServer(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/collaborator/server", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// fakeOpenOOB is a provider that reports an already-registered channel without opening anything.
// Registration() is the only method these tests reach, which is the point: the refusal must be
// decided from the provider's own account of itself, with no network and no subprocess.
type fakeOpenOOB struct {
	domain string
	server string
}

func (f *fakeOpenOOB) Channel(context.Context) (scanner.OOBChannel, error) {
	panic("Channel must not be called: deciding whether to refuse a server change may not open one")
}

func (f *fakeOpenOOB) Registration() scanner.OOBRegistration {
	return scanner.OOBRegistration{Attempted: true, Open: true, Domain: f.domain, Server: f.server}
}

func (f *fakeOpenOOB) Close() error { return nil }

// Setting a server on an installation that has none is the headline case, and it must leave the
// channel unregistered: the provider is lazy, so "configured" and "reachable" are different facts
// and a 200 here claims only the first.
func TestSettingTheCollaboratorServerConfiguresWithoutRegistering(t *testing.T) {
	ts := newTestServerWithScanner(t)

	rec := postCollaboratorServer(t, ts, `{"server":"https://oast.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}

	var status struct {
		Configured  bool   `json:"configured"`
		Server      string `json:"server"`
		State       string `json:"state"`
		Domain      string `json:"domain"`
		DefaultPool bool   `json:"default_pool"`
		Hint        string `json:"hint"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if !status.Configured {
		t.Error("configured=false after a successful set")
	}
	if status.Server != "https://oast.example" {
		t.Errorf("server = %q, want the URL that was set", status.Server)
	}
	if status.Domain != "" {
		t.Errorf("domain = %q — setting a server must not register a channel", status.Domain)
	}
	if status.DefaultPool {
		t.Error("default_pool=true for an explicit private server")
	}

	// And the scanner really holds it, rather than the endpoint having reported a value it stored
	// nowhere. This is the check that would have caught a decorative implementation.
	reg, configured := ts.wiredScanner().OOBRegistration()
	if !configured {
		t.Fatal("the scanner reports no provider, so the endpoint changed nothing")
	}
	if reg.Server != "https://oast.example" {
		t.Errorf("scanner's provider has server %q, want the one that was set", reg.Server)
	}
	if reg.Open || reg.Attempted {
		t.Errorf("provider already attempted/open (attempted=%v open=%v); it must stay lazy",
			reg.Attempted, reg.Open)
	}
}

// "public" must translate to the empty ServerURL that selects interactsh's own pool — the same
// translation main.go performs. If the two disagree, the same word means different things depending
// on which set it.
func TestPublicSelectsTheDefaultPool(t *testing.T) {
	ts := newTestServerWithScanner(t)

	rec := postCollaboratorServer(t, ts, `{"server":"public"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	var status struct {
		DefaultPool bool   `json:"default_pool"`
		Server      string `json:"server"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !status.DefaultPool {
		t.Error("default_pool=false for \"public\"")
	}
	if status.Server != "" {
		t.Errorf("server = %q, want empty — empty is what selects the pool", status.Server)
	}
}

// An empty server must be refused rather than silently meaning "public". Empty is how the internal
// Options field spells the default pool, but as operator input a blank box is far more likely to be
// an accident, and pointing out-of-band traffic at a public third party by accident is not
// acceptable.
func TestAnEmptyServerIsRefusedRatherThanMeaningPublic(t *testing.T) {
	ts := newTestServerWithScanner(t)

	for _, body := range []string{`{"server":""}`, `{"server":"   "}`, `{}`} {
		rec := postCollaboratorServer(t, ts, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: POST = %d, want 400", body, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "public") {
			t.Errorf("body %s: the refusal does not mention how to ask for the public pool: %s",
				body, rec.Body.String())
		}
	}

	// And nothing was configured by a refused request.
	if _, configured := ts.wiredScanner().OOBRegistration(); configured {
		t.Error("a refused request installed a provider anyway")
	}
}

// The refusal that matters. With a channel already registered, the change must be refused with the
// domain named, so the operator understands what they would have been detached from.
func TestChangingTheServerIsRefusedOnceAChannelIsRegistered(t *testing.T) {
	ts := newTestServerWithScanner(t)
	ts.wiredScanner().WithOOBProvider(&fakeOpenOOB{domain: "abc123.oast.example", server: "https://old.example"})

	rec := postCollaboratorServer(t, ts, `{"server":"https://new.example"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "abc123.oast.example") {
		t.Errorf("the refusal does not name the registered domain: %s", body)
	}

	// The old provider must still be installed. A refusal that had already swapped it would be the
	// worst of both: the operator told "no" while their channel was replaced.
	reg, configured := ts.wiredScanner().OOBRegistration()
	if !configured {
		t.Fatal("no provider after a refused change")
	}
	if reg.Domain != "abc123.oast.example" || reg.Server != "https://old.example" {
		t.Errorf("provider changed despite the 409: domain=%q server=%q", reg.Domain, reg.Server)
	}
}

// A provider that tried and failed must be replaceable. There is no domain and no correlated
// payload, so nothing can be orphaned — and a mistyped server is the most likely reason anyone
// reaches for this endpoint at all. Refusing here would leave the operator stuck with their typo.
func TestAFailedChannelCanStillBeReconfigured(t *testing.T) {
	ts := newTestServerWithScanner(t)
	// A server URL that cannot resolve, with a binary path that does not exist, so the first
	// registration attempt fails locally and quickly.
	ts.wiredScanner().WithOOBProvider(scanner.NewLazyOOBProvider(oob.Options{
		ServerURL:  "https://this-host-does-not-exist.invalid",
		BinaryPath: "/nonexistent/interactsh-client",
	}))
	// Force the attempt so the provider records its failure.
	if _, err := ts.wiredScanner().OOBChannel(t.Context()); err == nil {
		t.Skip("the bogus provider unexpectedly opened a channel; nothing to assert about failure")
	}

	reg, _ := ts.wiredScanner().OOBRegistration()
	if !reg.Attempted || reg.Open {
		t.Fatalf("precondition: want attempted-and-not-open, got attempted=%v open=%v",
			reg.Attempted, reg.Open)
	}

	rec := postCollaboratorServer(t, ts, `{"server":"https://good.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d, want 200 — a failed channel has nothing to orphan: %s",
			rec.Code, rec.Body.String())
	}
	newReg, _ := ts.wiredScanner().OOBRegistration()
	if newReg.Server != "https://good.example" {
		t.Errorf("server = %q, want the replacement", newReg.Server)
	}
	if newReg.Attempted {
		t.Error("the replacement provider is already marked attempted; it must start fresh")
	}
}

// With no scanner there is nothing that would ever consult the provider, so accepting the setting
// would store a value that changes nothing — a decorative control reached by another route.
func TestSettingTheServerWithNoScannerIsRefused(t *testing.T) {
	ts := newTestServer() // no scanner attached

	rec := postCollaboratorServer(t, ts, `{"server":"https://oast.example"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("POST = %d, want 503: %s", rec.Code, rec.Body.String())
	}
}

func TestCollaboratorServerRejectsNonPost(t *testing.T) {
	ts := newTestServerWithScanner(t)
	// DELETE is "Don't use Collaborator" (8e3n), tested in api_collaborator_health_test.go.
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		req := httptest.NewRequest(method, "/api/collaborator/server", nil)
		rec := httptest.NewRecorder()
		ts.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 405", method, rec.Code)
		}
	}
}

func TestCollaboratorServerRejectsAMalformedBody(t *testing.T) {
	ts := newTestServerWithScanner(t)
	rec := postCollaboratorServer(t, ts, `{"server":`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST = %d, want 400", rec.Code)
	}
}
