package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The unattended-caller gate (burpsy-react-ui-ejp5).
//
// These drive s.guarded rather than s.mux, because the gate is what is under test: a test that
// called the mux directly would pass whatever the gate did, including nothing at all. The
// cross-site gate is in the same chain, so these also prove the two compose.

// guarded drives one request through the whole chain, with the headers a same-origin call carries.
func guarded(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	return rec
}

// confirm mints a token for a route and returns it.
func confirm(t *testing.T, s *Server, pattern string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, pattern+"/confirm", nil)
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	rec := httptest.NewRecorder()
	// Through s.guarded, not s.mux: the mint is served from confirmMux and reached by the gate
	// routing to it, so a test that called s.mux would be testing a path no caller can take.
	s.guarded.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s/confirm = %d, want 200: %s", pattern, rec.Code, rec.Body.String())
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the confirm response: %v", err)
	}
	if body.Token == "" {
		t.Fatal("the confirm response carried no token")
	}
	return body.Token
}

// The gate's whole reason for existing: a confirmation-worthy route refuses a mutating call that
// carried no confirmation. Before this, only a browser dialog stood there, and a script never saw
// it.
func TestAConfirmationWorthyRouteRefusesAnUnconfirmedCall(t *testing.T) {
	s := newScannerServer()
	// POST /api/crawl is riskAttack — it sends unbounded traffic to a client's target.
	if rec := guarded(t, s, http.MethodPost, "/api/crawl", `{"seeds":["http://x/"]}`); rec.Code != http.StatusPreconditionRequired {
		t.Errorf("an unconfirmed POST to an attack route = %d, want %d: the gate is the only thing "+
			"between a caller that is not the console and live attack traffic",
			rec.Code, http.StatusPreconditionRequired)
	}
}

// A confirmed call proceeds. The gate is a per-call human decision, not a blanket refusal, and a
// gate that refused everything would be indistinguishable from having no route.
func TestAConfirmedCallProceeds(t *testing.T) {
	s := newScannerServer()
	token := confirm(t, s, "/api/crawl")
	req := httptest.NewRequest(http.MethodPost, "/api/crawl", strings.NewReader(`{"seeds":["http://x/"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	req.Header.Set(ConfirmHeader, token)
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code == http.StatusPreconditionRequired {
		t.Errorf("a confirmed POST to an attack route was still refused (%s): the gate must let a "+
			"call the operator authorised through", rec.Body.String())
	}
}

// A token is one-time. This is the property that stops a captured token from being a standing
// licence, and a gate that let it replay would be no gate at all against a caller that logs.
func TestAConfirmationCannotBeReplayed(t *testing.T) {
	s := newScannerServer()
	token := confirm(t, s, "/api/crawl")
	first := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/crawl", strings.NewReader(`{"seeds":["http://x/"]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Host = "127.0.0.1:8081"
		req.Header.Set("Origin", "http://127.0.0.1:8081")
		req.Header.Set(ConfirmHeader, token)
		rec := httptest.NewRecorder()
		s.guarded.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := first(); got == http.StatusPreconditionRequired {
		t.Fatal("a fresh token was refused; the gate is not spending tokens it issued")
	}
	if got := first(); got != http.StatusPreconditionRequired {
		t.Errorf("a REPLAYED token = %d, want %d: a confirmation that authorises more than one call "+
			"is not a confirmation", got, http.StatusPreconditionRequired)
	}
}

// A token issued for one route does not authorise another. Otherwise a caller that legitimately
// confirmed a cheap call could escalate to the expensive one with the same string.
func TestAConfirmationIsBoundToTheRouteItWasIssuedFor(t *testing.T) {
	s := newScannerServer()
	// /api/scope is riskScope; /api/crawl is riskAttack. Both gated, both different acts. The token
	// is minted and NOT spent, which is the point: an unspent token for the wrong route must not
	// carry.
	token := confirm(t, s, "/api/scope")
	if !s.confirms.pending(token) {
		t.Fatal("a freshly minted token does not read as pending; the store is broken before the " +
			"route binding is even tested")
	}
	if rec := guarded(t, s, http.MethodPost, "/api/crawl", `{"seeds":["http://x/"]}`); rec.Code != http.StatusPreconditionRequired {
		t.Errorf("a token minted for /api/scope authorised POST /api/crawl (%d): a confirmation "+
			"must be bound to the route it was issued for", rec.Code)
	}
}

// Reads are not gated. /api/scope is riskScope and answers GET with the scope list; gating that
// would mean the console cannot show the operator what they are about to confirm, which is the
// dialog this gate exists to back up.
func TestAReadOfAGatedRouteIsNotItselfGated(t *testing.T) {
	s := newScannerServer()
	if rec := guarded(t, s, http.MethodGet, "/api/scope", ""); rec.Code == http.StatusPreconditionRequired {
		t.Error("GET /api/scope was gated: the console must be able to READ the thing the operator " +
			"is being asked to confirm, or the dialog behind this gate has nothing to show")
	}
}

// Ungated classes stay ungated. A gate on everything is a gate nobody can satisfy.
func TestReadAndAssetRoutesAreNotGated(t *testing.T) {
	s := newScannerServer()
	for _, path := range []string{"/api/stats", "/api/advisories", "/api/history"} {
		if rec := guarded(t, s, http.MethodGet, path, ""); rec.Code == http.StatusPreconditionRequired {
			t.Errorf("GET %s was gated (%d): a read sends nothing and needs no confirmation", path, rec.Code)
		}
	}
}

// A garbage token is refused, and the refusal does not say WHY — "expired", "used" and "issued for
// another route" are three different answers, and telling a caller which one it got turns the
// endpoint into an oracle for probing live tokens.
func TestAnUnusableConfirmationSaysNothingAboutWhichFailureItWas(t *testing.T) {
	s := newScannerServer()
	rec := guarded(t, s, http.MethodPost, "/api/crawl", `{"seeds":["http://x/"]}`)
	var body struct {
		Error   string `json:"error"`
		Route   string `json:"route"`
		Risk    string `json:"risk"`
		Missing bool   `json:"missing"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the refusal is not the documented JSON shape: %v", err)
	}
	if !strings.Contains(body.Error, "confirm") {
		t.Errorf("the refusal does not say how to confirm: %q", body.Error)
	}
	if body.Route != "/api/crawl" {
		t.Errorf("the refusal names route %q, want /api/crawl — a caller must be able to tell which "+
			"call was refused", body.Route)
	}
	if body.Risk != string(riskAttack) {
		t.Errorf("the refusal names risk %q, want %q", body.Risk, riskAttack)
	}
}

// An expired token is refused. The TTL is a real bound and this is what enforces it; without the
// test, shortening ConfirmTTL to a nanosecond would look fine and mean nothing.
func TestAnExpiredConfirmationIsRefused(t *testing.T) {
	s := newScannerServer()
	token := confirm(t, s, "/api/crawl")
	// Age it past the TTL rather than sleeping: the test asserts the BOUND, not the wait.
	s.confirms.mu.Lock()
	e := s.confirms.tokens[token]
	e.expires = time.Now().Add(-time.Second)
	s.confirms.tokens[token] = e
	s.confirms.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/crawl", strings.NewReader(`{"seeds":["http://x/"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	req.Header.Set(ConfirmHeader, token)
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("an EXPIRED token = %d, want %d", rec.Code, http.StatusPreconditionRequired)
	}
}

// The mint endpoint is itself POST-only, and a GET must not hand out a token.
func TestAConfirmationCannotBeMintedWithAGet(t *testing.T) {
	s := newScannerServer()
	if rec := guarded(t, s, http.MethodGet, "/api/crawl/confirm", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/crawl/confirm = %d, want %d: minting a token must be a deliberate POST",
			rec.Code, http.StatusMethodNotAllowed)
	}
}

// The store bounds itself. A caller that mints and never spends must not grow the map without
// limit — a console left running for days is exactly the case.
func TestExpiredConfirmationsAreSweptRatherThanAccumulating(t *testing.T) {
	c := newConfirmStore()
	old, err := c.issue("/api/crawl")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	c.mu.Lock()
	e := c.tokens[old]
	e.expires = time.Now().Add(-time.Hour)
	c.tokens[old] = e
	c.mu.Unlock()
	fresh, err := c.issue("/api/crawl")
	if err != nil {
		t.Fatalf("second issue: %v", err)
	}
	c.mu.Lock()
	n := len(c.tokens)
	_, stillThere := c.tokens[old]
	c.mu.Unlock()
	if stillThere {
		t.Error("an expired confirmation survived the sweep: a store that only cleans on spend grows " +
			"without bound for a caller that never spends what it asks for")
	}
	if n != 1 {
		t.Errorf("the store holds %d tokens after a sweep, want 1", n)
	}
	if !c.pending(fresh) {
		t.Error("pending() says a fresh token is not pending")
	}
}

// Every gated pattern has a mint endpoint, derived rather than listed. A gated route with no mint
// endpoint is uncallable, and the console cannot supply the header the gate demands.
func TestEveryConfirmationWorthyRouteHasAMintEndpoint(t *testing.T) {
	s := newScannerServer()
	patterns := gatedRoutePatterns()
	if len(patterns) == 0 {
		t.Fatal("no gated patterns: the gate refuses every mutating call and permits none")
	}
	for _, pattern := range patterns {
		req := httptest.NewRequest(http.MethodPost, pattern+"/confirm", nil)
		req.Host = "127.0.0.1:8081"
		req.Header.Set("Origin", "http://127.0.0.1:8081")
		rec := httptest.NewRecorder()
		s.guarded.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
			t.Errorf("%s needs confirmation but POST %s/confirm is not routed (%d): a gate with no "+
				"way to satisfy it is a gate that forbids the route", pattern, pattern, rec.Code)
		}
	}
}

// A path that merely shares a prefix with a gated pattern is not gated. "/api/audit-elsewhere" is
// not "/api/audit/", and a prefix rule loose enough to catch it would gate a route the manifest
// never classified.
func TestAPrefixAloneDoesNotMakeARouteGated(t *testing.T) {
	if pathHasPrefix("/api/audit-elsewhere", "/api/audit/") {
		t.Error("pathHasPrefix matched across a segment boundary")
	}
	if !pathHasPrefix("/api/audit/7", "/api/audit/") {
		t.Error("pathHasPrefix failed on a real subtree path")
	}
	if !pathHasPrefix("/api/audit", "/api/audit") {
		t.Error("pathHasPrefix failed on an exact path")
	}
}

// burpsy-react-ui-r9b5: a confirmation is bound to the route it was minted for. A token minted for a
// cheap gated call (here, a crawl) must not confirm a different gated call (a CA private-key export)
// — before the fix the minted route was recorded and never compared, so any confirmation confirmed
// everything within its TTL.
func TestAConfirmationMintedForOneRouteIsRefusedOnAnother(t *testing.T) {
	s, _ := newTestServerWithCA(t)
	token := confirm(t, s, "/api/crawl")

	req := httptest.NewRequest(http.MethodPost, "/api/proxy/ca/export", strings.NewReader(`{"kind":"key"}`))
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	req.Header.Set(ConfirmHeader, token)
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("a crawl confirmation exported the CA private key (%d)", rec.Code)
	}
}

// The binding is to the subtree PAIR: /api/session/rules and /api/session/rules/ share one confirm
// endpoint, so a token from it spends on either — strict across routes, never refusing the route the
// caller minted for (the second half of r9b5: binding to one member at random would have failed about
// half of rule creates and edits).
func TestAConfirmationSpendsOnEitherMemberOfItsSubtreePair(t *testing.T) {
	s := newTestServer()
	for _, path := range []string{"/api/session/rules", "/api/session/rules/"} {
		if !s.confirms.spend(mustIssue(t, s, "/api/session/rules/"), path) {
			t.Errorf("a token minted at the pair's confirm endpoint was refused on %s", path)
		}
		if !s.confirms.spend(mustIssue(t, s, "/api/session/rules"), path) {
			t.Errorf("a token minted for the exact pattern was refused on %s", path)
		}
	}
	if s.confirms.spend(mustIssue(t, s, "/api/session/rules"), "/api/scope") {
		t.Error("a session-rules token spent on /api/scope")
	}
}

func mustIssue(t *testing.T, s *Server, pattern string) string {
	t.Helper()
	tok, err := s.confirms.issue(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
