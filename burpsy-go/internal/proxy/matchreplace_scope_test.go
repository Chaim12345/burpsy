package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"go.uber.org/zap"
)

// ---- "Only apply to in-scope items" (burpsy-react-ui-rfgs) --------------------------------------
//
// Burp's Match and Replace panel has one scope control and it is panel-wide: a checkbox, wired to
// `proxy.match_replace_disable_out_of_scope` (ConfigPanelProxyHttpMatchAndReplaceRules001:171), that
// stops every rule in the table from touching a message the Target scope excludes. The persisted rule
// itself has no scope — its six fields are rule_type, enabled, category, string_match, string_replace
// and comment (Zejh.ZY), and the rule table has no scope column (CoreComponent5002) — which is why the
// feature is a switch beside the rules rather than a field on them.
//
// The tests here are about the *decision*, not the flag: the flag is a boolean and a boolean is not
// worth a test. What is worth pinning is that an out-of-scope message is left byte-identical on the
// wire, that an in-scope one is not, and that the gate reports what it turned away — that last one
// because a restriction that silently does nothing and one that silently refuses everything look the
// same from the outside.

// scopeFixture builds the proxy, the origin and the rule set for the HTTP cases.
//
// The origin reports back what it actually received, so every assertion is about the bytes that
// crossed the wire rather than about what the store chose to keep — the same standard the existing
// wiring test holds itself to, and the reason it is here rather than inspecting a counter.
type scopeFixture struct {
	rules   *matchreplace.RuleSet
	got     func() (path, secret, body string)
	respond func() string
}

func newScopeFixture(t *testing.T, scope *core.Scope, inScopeOnly bool) *scopeFixture {
	t.Helper()

	var gotPath, gotSecret, gotBody string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotSecret = r.Header.Get("X-Secret")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		io.WriteString(w, "wrap RESP-ORIG wrap")
	}))
	t.Cleanup(origin.Close)

	thost, tportStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	tport, _ := strconv.Atoi(tportStr)

	rules := matchreplace.NewRuleSet()
	rules.SetRules([]*matchreplace.Rule{
		mustRule(t, matchreplace.TargetRequestFirstLine, matchreplace.CategoryLiteral, "/orig", "/rewritten"),
		mustRule(t, matchreplace.TargetRequestHeader, matchreplace.CategoryLiteral, "hunter2", "scrubbed"),
		mustRule(t, matchreplace.TargetResponseBody, matchreplace.CategoryLiteral, "RESP-ORIG", "RESP-PROXY"),
	})
	rules.SetInScopeOnly(inScopeOnly)

	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(scope).
		WithMatchReplace(rules).
		WithLogger(zap.NewNop()))
	proxyAddr := serveProxy(t, srv)

	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
	}}

	return &scopeFixture{
		rules: rules,
		got:   func() (string, string, string) { return gotPath, gotSecret, gotBody },
		respond: func() string {
			req, err := http.NewRequest(http.MethodPost,
				fmt.Sprintf("http://%s:%d/orig", thost, tport), strings.NewReader("body REQ-IN body"))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("X-Secret", "hunter2")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request through proxy: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return string(body)
		},
	}
}

// TestInScopeOnlyLeavesAnOutOfScopeExchangeByteIdentical is the headline case: the rules exist, are
// enabled, and would match — and an out-of-scope exchange goes past untouched, in both directions.
func TestInScopeOnlyLeavesAnOutOfScopeExchangeByteIdentical(t *testing.T) {
	f := newScopeFixture(t, outOfScope(), true)

	respBody := f.respond()
	path, secret, body := f.got()

	if path != "/orig" {
		t.Errorf("origin saw path %q, want /orig — the restriction must stop the request_first_line rule", path)
	}
	if secret != "hunter2" {
		t.Errorf("origin saw X-Secret %q, want hunter2 — the restriction must stop the request_header rule", secret)
	}
	if body != "body REQ-IN body" {
		t.Errorf("origin saw body %q, want the client's own bytes", body)
	}
	if !strings.Contains(respBody, "RESP-ORIG") || strings.Contains(respBody, "RESP-PROXY") {
		t.Errorf("client received %q; the response rule ran on an out-of-scope exchange", respBody)
	}
}

// TestInScopeOnlyDoesNotTouchInScopeTraffic is the other half of the claim, and the one that keeps the
// first half from passing for the wrong reason: with the restriction on, in-scope traffic is rewritten
// exactly as it would be with the restriction off.
func TestInScopeOnlyDoesNotTouchInScopeTraffic(t *testing.T) {
	f := newScopeFixture(t, testScope(), true)

	respBody := f.respond()
	path, secret, body := f.got()

	if path != "/rewritten" || secret != "scrubbed" || body != "body REQ-IN body" {
		t.Errorf("origin saw (%q, %q, %q); an in-scope exchange must be rewritten as usual",
			path, secret, body)
	}
	if !strings.Contains(respBody, "RESP-PROXY") {
		t.Errorf("client received %q, want the rewritten response", respBody)
	}
	// Nothing was excluded, so nothing was counted as excluded. A counter that rose here would be
	// reporting refusals that never happened.
	if n := f.rules.ScopeSkipped(); n != 0 {
		t.Errorf("ScopeSkipped = %d with an in-scope target, want 0", n)
	}
}

// TestTheRestrictionOffRewritesOutOfScopeTraffic pins the default and the upgrade path: with the
// switch off — which is Burp's default and every project saved before this existed — an out-of-scope
// exchange is rewritten exactly as it was before the gate existed.
func TestTheRestrictionOffRewritesOutOfScopeTraffic(t *testing.T) {
	f := newScopeFixture(t, outOfScope(), false)

	respBody := f.respond()
	path, secret, _ := f.got()

	if path != "/rewritten" || secret != "scrubbed" {
		t.Errorf("origin saw (%q, %q); with the restriction off the rules must run on every exchange, "+
			"in scope or not", path, secret)
	}
	if !strings.Contains(respBody, "RESP-PROXY") {
		t.Errorf("client received %q, want the rewritten response", respBody)
	}
	if n := f.rules.ScopeSkipped(); n != 0 {
		t.Errorf("ScopeSkipped = %d with the restriction off, want 0", n)
	}
}

// TestTheRestrictionReportsEachDirectionItTurnedAway checks the evidence an operator has.
//
// The count is per message-direction, not per exchange: the request rule and the response rule are two
// separate decisions against two separately-scoped questions, and folding them into one per exchange
// would make a half-rewritten exchange (a request in scope, its response not) unreportable.
func TestTheRestrictionReportsEachDirectionItTurnedAway(t *testing.T) {
	f := newScopeFixture(t, outOfScope(), true)

	f.respond()

	if n := f.rules.ScopeSkipped(); n != 2 {
		t.Errorf("ScopeSkipped = %d after one out-of-scope exchange with a request rule and a response "+
			"rule, want 2 — the gate turns away each direction's message separately, and a rule that "+
			"stopped matching because scope was narrowed must be distinguishable from one that stopped "+
			"matching because the site changed", n)
	}
}

// TestAnOutOfScopeWebSocketIsNeverParsed is the WebSocket half, and it also pins a deliberate trade:
// frames are only reassembled when there is something that needs whole messages. An out-of-scope
// connection with the restriction on and interception off has nothing — so the relay stays opaque, the
// payload is byte-identical, and nothing is counted, because nothing was ever offered to the gate.
//
// The count staying at zero is the point of the second assertion rather than a gap in it: reporting a
// number of messages for a connection the relay deliberately never parsed would mean inventing a
// message count.
func TestAnOutOfScopeWebSocketIsNeverParsed(t *testing.T) {
	srv, rules := wsScopeServer(t, outOfScope(), true, nil)

	mask := [4]byte{1, 2, 3, 4}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"role":"user"}`), &mask)

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if string(got) != string(frame) {
		t.Errorf("relayed % x, want the frame unchanged — an out-of-scope WebSocket must go past "+
			"untouched", got)
	}
	if n := rules.ScopeSkipped(); n != 0 {
		t.Errorf("ScopeSkipped = %d for a connection the relay never reassembled, want 0", n)
	}
}

// TestAnOutOfScopeWebSocketIsReportedWhenInterceptionForcesTheFramePath is the same connection with
// interception on, which reassembles frames for its own reason. Now the gate *is* reached, the message
// is turned away, and it says so — so the zero in the test above is "never looked" and not "looked and
// found nothing to count".
func TestAnOutOfScopeWebSocketIsReportedWhenInterceptionForcesTheFramePath(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv, rules := wsScopeServer(t, outOfScope(), true, engine)

	mask := [4]byte{5, 6, 7, 8}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"role":"user"}`), &mask)

	stop := wsOperator(engine, func(h *intercept.Held) { _ = engine.Forward(h.ID, nil, false, nil) })
	defer stop()

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	_, payload, _ := wsDecodeOne(t, got)
	if string(payload) != `{"role":"user"}` {
		t.Errorf("server received %q, want the payload unrewritten", payload)
	}
	if n := rules.ScopeSkipped(); n != 1 {
		t.Errorf("ScopeSkipped = %d after one out-of-scope message reached the frame path, want 1", n)
	}
}

// TestAnInScopeWebSocketIsStillRewritten is the control for the two tests above: the restriction does
// not turn the WebSocket rules off, it narrows them.
func TestAnInScopeWebSocketIsStillRewritten(t *testing.T) {
	srv, _ := wsScopeServer(t, testScope(), true, nil)

	mask := [4]byte{9, 9, 9, 9}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"role":"user"}`), &mask)

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	_, payload, _ := wsDecodeOne(t, got)
	if string(payload) != `{"role":"admin"}` {
		t.Errorf("server received %q, want the rewritten payload — an in-scope WebSocket must be "+
			"rewritten with the restriction on", payload)
	}
}

// wsScopeServer is wsRuleServer with a scope and the restriction under test. The rule rewrites the
// to-server payload, so "did the restriction work" is visible in the bytes the peer received.
func wsScopeServer(t *testing.T, scope *core.Scope, inScopeOnly bool, engine *intercept.Engine) (*Server, *matchreplace.RuleSet) {
	t.Helper()
	rs := matchreplace.NewRuleSet()
	rs.SetRules([]*matchreplace.Rule{wsRule(t, matchreplace.TargetWebSocketToServer, "user", "admin")})
	rs.SetInScopeOnly(inScopeOnly)
	cfg := NewProxyConfig(core.NewTrafficStore()).
		WithScope(scope).
		WithLogger(zap.NewNop()).
		WithMatchReplace(rs)
	if engine != nil {
		cfg = cfg.WithIntercept(engine)
	}
	return NewServer(cfg), rs
}

// The tests above drive wsRun's fixed peer — chat.test:443/ws — so the scope they are given has to
// exclude or include *that*, not the HTTP fixture's origin. Stated as an assertion rather than a
// comment because a scope helper that stopped excluding chat.test would make the out-of-scope cases
// pass for the wrong reason: wsRun does not take a target, so nothing else would notice.
func TestWsScopeFixturesDisagreeAboutChatTest(t *testing.T) {
	if outOfScope().Contains("chat.test", 443, "/ws", true) {
		t.Error("outOfScope() covers chat.test, so every out-of-scope WebSocket test below would be " +
			"testing an in-scope connection")
	}
	if !testScope().Contains("chat.test", 443, "/ws", true) {
		t.Error("testScope() does not cover chat.test, so the in-scope WebSocket control would be " +
			"testing an excluded connection")
	}
}
