package intercept

import (
	"testing"
	"time"
)

func reqMessage(host, method, path string) *Message {
	return &Message{
		Direction: DirectionRequest,
		Host:      host,
		Port:      80,
		Method:    method,
		Path:      path,
		Raw:       []byte(method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
	}
}

func respMessage(host, method, path string, status int, raw []byte) *Message {
	if raw == nil {
		raw = []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n")
	}
	return &Message{
		Direction:   DirectionResponse,
		Host:        host,
		Port:        80,
		Method:      method,
		Path:        path,
		Status:      &status,
		ContentType: "text/html",
		Raw:         raw,
	}
}

func TestEngine_OffByDefaultHoldsNothing(t *testing.T) {
	e := NewEngine()
	if e.Hold(reqMessage("a.test", "GET", "/")) != nil {
		t.Fatalf("engine with both lists off held a message")
	}
}

func TestEngine_UnconditionalListHoldsEverything(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.SetRules(DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	h := e.Hold(reqMessage("a.test", "GET", "/"))
	if h == nil {
		t.Fatalf("unconditional request list did not hold")
	}
	if h.Direction != DirectionRequest || h.Host != "a.test" || h.Path != "/" {
		t.Fatalf("held = %+v", h)
	}
	// Resolve it so the map has no dangling entry.
	if err := e.Forward(h.ID, nil, false); err != nil {
		t.Fatalf("Forward: %v", err)
	}
}

func TestEngine_SelectiveRuleHoldsOnlyMatches(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	rule, err := NewRule(FieldHost, CategoryLiteral, "internal", true, "", RuleActionHold)
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	if err := e.SetRules(DirectionRequest, true, []Rule{*rule}); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	if e.Hold(reqMessage("api.internal.test", "GET", "/")) == nil {
		t.Fatalf("matching host was not held")
	}
	if e.Hold(reqMessage("public.test", "GET", "/")) != nil {
		t.Fatalf("non-matching host was held")
	}
}

func TestEngine_DisabledRuleHoldsNothing(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	rule, err := NewRule(FieldHost, CategoryLiteral, "internal", false, "", RuleActionHold)
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	if err := e.SetRules(DirectionRequest, true, []Rule{*rule}); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	if e.Hold(reqMessage("api.internal.test", "GET", "/")) != nil {
		t.Fatalf("disabled rule held a message")
	}
}

func TestEngine_RegexRuleMatchesPath(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	rule, err := NewRule(FieldPath, CategoryRegex, `^/admin/.*`, true, "", RuleActionHold)
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	if err := e.SetRules(DirectionRequest, true, []Rule{*rule}); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	if e.Hold(reqMessage("a.test", "GET", "/admin/users")) == nil {
		t.Fatalf("matching path not held")
	}
	if e.Hold(reqMessage("a.test", "GET", "/public")) != nil {
		t.Fatalf("non-matching path held")
	}
}

func TestEngine_SetRulesRefusesBadRegex(t *testing.T) {
	e := NewEngine()
	bad := Rule{Field: FieldPath, Category: CategoryRegex, StringMatch: "[", Enabled: true}
	if err := e.SetRules(DirectionRequest, true, []Rule{bad}); err == nil {
		t.Fatalf("SetRules accepted a malformed regex")
	}
	// The list must be unchanged.
	l := e.Rules(DirectionRequest)
	if l.Active {
		t.Fatalf("bad regex changed the list")
	}
}

func TestEngine_HeldForwardCarriesEditedBytes(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetRules(DirectionRequest, true, nil)
	m := reqMessage("a.test", "GET", "/")
	h := e.Hold(m)
	if h == nil {
		t.Fatalf("not held")
	}
	edited := "GET /changed HTTP/1.1\r\nHost: a.test\r\n\r\n"
	go func() {
		time.Sleep(20 * time.Millisecond)
		if err := e.Forward(h.ID, ptr(edited), false); err != nil {
			t.Errorf("Forward: %v", err)
		}
	}()
	action, raw := h.Wait()
	if action != ActionForward {
		t.Fatalf("action = %v, want forward", action)
	}
	if string(raw) != edited {
		t.Fatalf("raw = %q, want edited %q", raw, edited)
	}
}

func TestEngine_DropResolvesToNilBytes(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetRules(DirectionResponse, true, nil)
	m := respMessage("a.test", "GET", "/", 200, nil)
	h := e.Hold(m)
	if h == nil {
		t.Fatalf("not held")
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		if err := e.Drop(h.ID, "not interesting"); err != nil {
			t.Errorf("Drop: %v", err)
		}
	}()
	action, raw := h.Wait()
	if action != ActionDrop {
		t.Fatalf("action = %v, want drop", action)
	}
	if raw != nil {
		t.Fatalf("dropped raw = %q, want nil", raw)
	}
}

func TestEngine_ResolvingHeldMessageRemovesItFromTheMap(t *testing.T) {
	// Regression for the C1 memory leak: Forward/Drop previously resolved a held
	// message but never deleted it from e.held, so a long-running proxy leaked
	// one full raw message per intercepted exchange. After resolve+delete, the
	// hold map must be empty again.
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.SetRules(DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}

	for i := 0; i < 50; i++ {
		h := e.Hold(reqMessage("a.test", "GET", "/"))
		if h == nil {
			t.Fatalf("iteration %d: message not held", i)
		}
		if err := e.Forward(h.ID, nil, false); err != nil {
			t.Fatalf("iteration %d: Forward: %v", i, err)
		}
	}
	if n := len(e.held); n != 0 {
		t.Fatalf("hold map has %d entries after forwarding 50 held messages, want 0 (memory leak)", n)
	}

	// Drop path deletes too.
	h := e.Hold(reqMessage("a.test", "GET", "/"))
	if h == nil {
		t.Fatalf("message not held")
	}
	if err := e.Drop(h.ID, "test"); err != nil {
		t.Fatalf("Drop: %v", err)
	}
	if n := len(e.held); n != 0 {
		t.Fatalf("hold map has %d entries after a drop, want 0", n)
	}
}

func TestEngine_SecondResolveIsIgnored(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetRules(DirectionRequest, true, nil)
	h := e.Hold(reqMessage("a.test", "GET", "/"))
	if err := e.Forward(h.ID, nil, false); err != nil {
		t.Fatalf("first Forward: %v", err)
	}
	if err := e.Forward(h.ID, ptr("GET /again HTTP/1.1\r\n\r\n"), false); err == nil {
		t.Fatalf("second Forward succeeded, want error")
	}
	if err := e.Drop(h.ID, ""); err == nil {
		t.Fatalf("Drop after Forward succeeded, want error")
	}
}

func TestEngine_ForwardUnknownIDFails(t *testing.T) {
	e := NewEngine()
	if err := e.Forward(99, nil, false); err == nil {
		t.Fatalf("Forward on unknown id succeeded")
	}
}

func TestEngine_ResponseFields(t *testing.T) {
	// status and content type come from the raw response bytes.
	raw := []byte("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
	m := ParseMessage(DirectionResponse, "a.test", 80, false, "GET", "/x", raw)
	if m.Status == nil || *m.Status != 404 {
		t.Fatalf("status = %v, want 404", m.Status)
	}
	if m.ContentType != "application/json" {
		t.Fatalf("content type = %q", m.ContentType)
	}
	rule, err := NewRule(FieldStatusCode, CategoryLiteral, "404", true, "", RuleActionHold)
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	if !rule.Match(m) {
		t.Fatalf("status rule did not match")
	}
}

func TestRewriteContentLength(t *testing.T) {
	in := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\nhi")
	out := rewriteContentLength(in)
	want := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nhi"
	if string(out) != want {
		t.Fatalf("got %q, want %q", out, want)
	}
}

func TestRewriteContentLength_ChunkedUntouched(t *testing.T) {
	in := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
	out := rewriteContentLength(in)
	if string(out) != string(in) {
		t.Fatalf("chunked message changed: %q", out)
	}
}

func TestExtensionOf(t *testing.T) {
	cases := map[string]string{
		"/img/logo.png":         "png",
		"/":                     "",
		"/search":               "",
		"/a.b/c":                "",
		"/download/file.tar.gz": "gz",
	}
	for in, want := range cases {
		if got := extensionOf(in); got != want {
			t.Errorf("extensionOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMessageURL(t *testing.T) {
	m := &Message{Direction: DirectionRequest, Host: "a.test", Port: 8080, TLS: false, Path: "/x"}
	if got := m.URL(); got != "http://a.test:8080/x" {
		t.Fatalf("url = %q", got)
	}
	m.TLS = true
	if got := m.URL(); got != "https://a.test:8080/x" {
		t.Fatalf("tls url = %q", got)
	}
	m.Port = 443
	if got := m.URL(); got != "https://a.test/x" {
		t.Fatalf("default-port url = %q", got)
	}
	m.Host = "2001:db8::1"
	m.Port = 443
	if got := m.URL(); got != "https://[2001:db8::1]/x" {
		t.Fatalf("ipv6 url = %q", got)
	}
}

func TestHeld_StatusField(t *testing.T) {
	m := reqMessage("a.test", "GET", "/")
	if m.FieldValue(FieldStatusCode) != "" {
		t.Fatalf("request status_code should be empty")
	}
	code := 500
	m.Status = &code
	if got := m.FieldValue(FieldStatusCode); got != "500" {
		t.Fatalf("status_code = %q", got)
	}
}

func TestEngine_DropAllDropsEveryHeldMessageAndCountsOnlyItsOwn(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetRules(DirectionRequest, true, nil)
	first := e.Hold(reqMessage("a.test", "GET", "/one"))
	second := e.Hold(reqMessage("a.test", "GET", "/two"))
	if first == nil || second == nil {
		t.Fatalf("expected both messages held")
	}
	// Resolve one out from under DropAll: it must not be counted or re-resolved,
	// because the proxy side of that message already has its answer.
	if err := e.Forward(first.ID, nil, false); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if got := e.DropAll("clear the queue"); got != 1 {
		t.Fatalf("DropAll = %d, want 1 (the forwarded message was already resolved)", got)
	}
	if left := len(e.Held()); left != 0 {
		t.Fatalf("queue not empty after DropAll: %d left", left)
	}
	// The dropped message's proxy side wakes with a drop and no bytes.
	action, raw := second.Wait()
	if action != ActionDrop || raw != nil {
		t.Fatalf("Wait = (%v, %q), want (drop, nil)", action, raw)
	}
	// An empty queue drops nothing and says so.
	if got := e.DropAll("again"); got != 0 {
		t.Fatalf("DropAll on an empty queue = %d, want 0", got)
	}
}

// ForwardAll is the safe half of the DropAll pair, and it must be exactly that:
// every held message released with the bytes the client sent and nothing added
// — no edit, no content-length rewrite, because a bulk action never had a human
// read what it forwards. A queue that can only be emptied by dropping teaches
// the operator to stop queueing traffic at all, which is why Burp ships both
// halves from one dropdown (proxyForwardOptionsButton).
func TestEngine_ForwardAllForwardsEveryHeldMessageUnmodifiedAndCountsOnlyItsOwn(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetRules(DirectionRequest, true, nil)
	first := e.Hold(reqMessage("a.test", "GET", "/one"))
	second := e.Hold(reqMessage("a.test", "POST", "/two"))
	if first == nil || second == nil {
		t.Fatalf("expected both messages held")
	}
	// Resolve one out from under ForwardAll: it must not be counted or
	// re-resolved, because the proxy side of that message already has its answer.
	if err := e.Drop(first.ID, "resolved first"); err != nil {
		t.Fatalf("Drop: %v", err)
	}
	if got := e.ForwardAll(); got != 1 {
		t.Fatalf("ForwardAll = %d, want 1 (the dropped message was already resolved)", got)
	}
	if left := len(e.Held()); left != 0 {
		t.Fatalf("queue not empty after ForwardAll: %d left", left)
	}
	// The forwarded message's proxy side wakes with a forward and the exact
	// bytes the client put on the wire — the rewriteContentLength pass that a
	// per-id Forward applies on request has no place here.
	action, raw := second.Wait()
	if action != ActionForward {
		t.Fatalf("Wait action = %v, want forward", action)
	}
	if string(raw) != string(second.Raw) {
		t.Fatalf("Wait raw = %q, want the client's own bytes %q", raw, second.Raw)
	}
	// An empty queue forwards nothing and says so.
	if got := e.ForwardAll(); got != 0 {
		t.Fatalf("ForwardAll on an empty queue = %d, want 0", got)
	}
}

// ptr is for the *string argument Forward now takes: nil means "forward unchanged", and a pointer
// to the empty string means "clear the payload". Those were the same value before, which is the
// defect this signature fixes.
func ptr[T any](v T) *T { return &v }
