package proxy

import (
	"bytes"
	"io"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"go.uber.org/zap"
)

// ---- WebSocket match & replace (issue 4lh) --------------------------------------------------
//
// Burp rewrites WebSocket payloads with standing match/replace rules; burpsy's rule set had HTTP
// targets only, so there was nothing a WebSocket rule could be written against.
//
// The most important test here is TestWebSocketRulesApplyWithInterceptionOff. Frame parsing existed
// only for interception, so the obvious implementation — rewriting inside the hold path — would have
// installed rules, reported success, and rewritten nothing whenever interception was off. That is the
// decorative-control failure this project keeps finding, and I had it briefly during this work.

func wsRuleServer(t *testing.T, engine *intercept.Engine, rules ...*matchreplace.Rule) *Server {
	t.Helper()
	rs := matchreplace.NewRuleSet()
	rs.SetRules(rules)
	cfg := NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithMatchReplace(rs)
	if engine != nil {
		cfg = cfg.WithIntercept(engine)
	}
	return NewServer(cfg)
}

func wsRule(t *testing.T, target matchreplace.Target, match, replace string) *matchreplace.Rule {
	t.Helper()
	r, err := matchreplace.NewRule(target, matchreplace.CategoryLiteral, match, replace, "test rule")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	return r
}

// The headline case, and the one that would have been silently broken: no interception at all, just a
// standing rule.
func TestWebSocketRulesApplyWithInterceptionOff(t *testing.T) {
	srv := wsRuleServer(t, nil, wsRule(t, matchreplace.TargetWebSocketToServer, "user", "admin"))

	mask := [4]byte{1, 2, 3, 4}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"role":"user"}`), &mask)

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	_, payload, masked := wsDecodeOne(t, got)
	if string(payload) != `{"role":"admin"}` {
		t.Errorf("server received %q, want the rewritten payload — a WebSocket match/replace rule "+
			"must fire whether or not interception is on", payload)
	}
	if !masked {
		t.Error("the rewritten client frame went out unmasked; the server must fail the connection")
	}
}

// A rule for the other direction must not fire on this one. The old targetsDir was an if-chain that
// treated every non-request direction as a response, which is exactly how a WebSocket payload would
// have been matched against the wrong list.
func TestAWebSocketRuleOnlyFiresInItsOwnDirection(t *testing.T) {
	// A to-client rule, driving the to-server direction.
	srv := wsRuleServer(t, nil, wsRule(t, matchreplace.TargetWebSocketToClient, "user", "admin"))

	mask := [4]byte{5, 6, 7, 8}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"role":"user"}`), &mask)

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if !bytes.Equal(got, frame) {
		t.Errorf("a to-client rule rewrote a to-server frame: got % x want % x", got, frame)
	}
}

// The server-to-client direction, which must go out unmasked.
func TestAToClientRuleRewritesAndLeavesTheFrameUnmasked(t *testing.T) {
	srv := wsRuleServer(t, nil, wsRule(t, matchreplace.TargetWebSocketToClient, "10", "999999"))

	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"balance":10}`), nil)

	got, fault, _ := wsRun(t, srv, false, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	_, payload, masked := wsDecodeOne(t, got)
	if masked {
		t.Error("a server→client frame was masked; RFC 6455 forbids it and the client must fail")
	}
	if string(payload) != `{"balance":999999}` {
		t.Errorf("client received %q, want the rewritten payload", payload)
	}
}

// An HTTP-targeted rule must never touch a WebSocket payload. Sharing one rule set between HTTP and
// WebSocket is only safe if the targets keep them apart.
func TestAnHTTPRuleDoesNotRewriteAWebSocketPayload(t *testing.T) {
	srv := wsRuleServer(t, nil,
		wsRule(t, matchreplace.TargetRequestBody, "user", "admin"),
		wsRule(t, matchreplace.TargetResponseBody, "user", "admin"),
	)

	mask := [4]byte{9, 9, 9, 9}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"role":"user"}`), &mask)

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if !bytes.Equal(got, frame) {
		t.Errorf("an HTTP-targeted rule rewrote a WebSocket payload: got % x want % x", got, frame)
	}
}

// A rule matching nothing must leave the frame byte-identical, mask included — indistinguishable
// from a proxy with no rules at all.
func TestANonMatchingRuleLeavesTheFrameByteIdentical(t *testing.T) {
	srv := wsRuleServer(t, nil, wsRule(t, matchreplace.TargetWebSocketToServer, "absent", "x"))

	mask := [4]byte{3, 1, 4, 1}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"role":"user"}`), &mask)

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if !bytes.Equal(got, frame) {
		t.Errorf("relayed % x, want % x", got, frame)
	}
}

// Rewrite happens before interception, so the operator sees the message they will actually forward.
// The other order would show them one thing and send another.
func TestAWebSocketRuleAppliesBeforeInterceptionSeesTheMessage(t *testing.T) {
	engine := holdEverything(t, intercept.DirectionWebSocketToServer)
	srv := wsRuleServer(t, engine, wsRule(t, matchreplace.TargetWebSocketToServer, "user", "admin"))

	mask := [4]byte{2, 7, 1, 8}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte(`{"role":"user"}`), &mask)

	var offered []string
	stop := wsOperator(engine, func(h *intercept.Held) {
		offered = append(offered, string(h.Raw))
		_ = engine.Forward(h.ID, nil, false)
	})
	defer stop()

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	if len(offered) != 1 {
		t.Fatalf("offered %d messages, want 1", len(offered))
	}
	if offered[0] != `{"role":"admin"}` {
		t.Errorf("the operator was shown %q; match & replace must run first so what they see is what "+
			"they forward", offered[0])
	}
	// And the rewrite must reach the wire even though the operator changed nothing further.
	_, payload, _ := wsDecodeOne(t, got)
	if string(payload) != `{"role":"admin"}` {
		t.Errorf("server received %q; forwarding an unedited message must not discard the rewrite", payload)
	}
}

// A rewrite applies to the reassembled message, not to each fragment, so a rule can match across a
// fragment boundary — the thing fragment reassembly makes possible.
func TestARuleCanMatchAcrossAFragmentBoundary(t *testing.T) {
	srv := wsRuleServer(t, nil, wsRule(t, matchreplace.TargetWebSocketToServer, "abcdef", "REWRITTEN"))

	// "abc" + "def" as one fragmented text message; neither fragment contains the pattern.
	input := []byte{0x01, 0x03, 'a', 'b', 'c', 0x80, 0x03, 'd', 'e', 'f'}

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(input) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	opcode, payload, _ := wsDecodeOne(t, got)
	if opcode != core.WsOpcodeText {
		t.Errorf("opcode = %v, want text (from the first fragment)", opcode)
	}
	if string(payload) != "REWRITTEN" {
		t.Errorf("payload = %q, want REWRITTEN — a rule must see the whole message, not one "+
			"fragment at a time", payload)
	}
}

// Content-Length must not be injected into a payload that happens to contain a blank line. The HTTP
// applier recomputes it after a body rewrite; a frame has no such header, and adding one would
// corrupt application data.
func TestARewrittenPayloadDoesNotGainAContentLengthHeader(t *testing.T) {
	rs := matchreplace.NewRuleSet()
	rs.SetRules([]*matchreplace.Rule{wsRule(t, matchreplace.TargetWebSocketToServer, "old", "new")})
	rs.SetUpdateContentLength(true)
	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).WithLogger(zap.NewNop()).WithMatchReplace(rs))

	// A payload with a blank line in it, which is what fixContentLength would read as a
	// header/body boundary.
	mask := [4]byte{1, 1, 2, 2}
	frame := core.EncodeWsFrame(core.WsOpcodeText, []byte("head: old\r\n\r\nbody old"), &mask)

	got, fault, _ := wsRun(t, srv, true, func(w io.Writer) { _, _ = w.Write(frame) })
	if fault != "" {
		t.Fatalf("unexpected fault: %s", fault)
	}
	_, payload, _ := wsDecodeOne(t, got)
	if bytes.Contains(payload, []byte("Content-Length")) {
		t.Errorf("a Content-Length header was injected into a WebSocket payload: %q", payload)
	}
	if string(payload) != "head: new\r\n\r\nbody new" {
		t.Errorf("payload = %q, want both occurrences rewritten and nothing added", payload)
	}
}
