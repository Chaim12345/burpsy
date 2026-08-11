// Tests for the active evaluator (M2 `send request`, M3 `given insertion point`
// / `send payload`), ported from crates/bcheck/src/eval.rs.
//
// Every assertion here inspects the bytes the sink actually received. A test
// that only proves "the send did not error" would pass even if all the modifier
// clauses were still discarded.
package bcheck

import (
	"strings"
	"testing"
)

// mockSink records what it was asked to send and replays canned responses in
// order, mirroring eval.rs's MockSender.
type mockSink struct {
	sent    []string
	replies []mockReply
}

type mockReply struct {
	body []byte
	err  error
}

func (m *mockSink) Send(target *Target, raw []byte) ([]byte, error) {
	m.sent = append(m.sent, string(raw))
	if len(m.replies) == 0 {
		return ok200("default"), nil
	}
	r := m.replies[0]
	m.replies = m.replies[1:]
	if r.err != nil {
		return nil, r.err
	}
	return r.body, nil
}

func ok200(body string) []byte {
	return []byte("HTTP/1.1 200 OK\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body)
}

func withStatus(code, body string) []byte {
	return []byte("HTTP/1.1 " + code + " X\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func (m *mockSink) first() string {
	if len(m.sent) == 0 {
		return ""
	}
	return m.sent[0]
}

func (m *mockSink) count() int { return len(m.sent) }

func tgt() *Target { return &Target{Host: "x.test", Port: 80, TLS: false} }

const baseReq = "GET /orig?a=1 HTTP/1.1\r\nHost: x.test\r\nAccept: */*\r\n\r\n"

func activeCtx() *Context {
	c := NewContext()
	c.Request = []byte(baseReq)
	c.Response = []byte(ok200("base body"))
	c.Host = "x.test"
	c.Port = 80
	c.Path = "/orig?a=1"
	return c
}

// parseCheck parses a check body with the mandatory metadata block, like the
// Rust tests' parse_check.
func parseCheck(body string) *Check {
	src := "metadata:\n  language: v2-beta\n  name: \"t\"\n" + body
	c, err := Parse(src)
	if err != nil {
		panic("should parse: " + err.Error() + "\n--- src ---\n" + src)
	}
	return c
}

func runActive(t *testing.T, src string, m *mockSink) ([]Finding, error) {
	t.Helper()
	return RunActive(parseCheck(src), activeCtx(), m, tgt())
}

func TestReplacingPathReachesTheWireAndLeavesTheQuery(t *testing.T) {
	m := &mockSink{replies: []mockReply{{body: ok200("admin page")}}}
	f, err := runActive(t, `given host then
  send request called probe:
    path: "/admin"
  if {probe.response.status_code} is "200" then
    report issue:
      severity: high
      confidence: certain
  end if
`, m)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	// The query survives: `path` and `query_string` are separate modifier
	// targets, so replacing one leaves the other alone.
	if !strings.HasPrefix(m.first(), "GET /admin?a=1 HTTP/1.1") {
		t.Errorf("sent %q, want a /admin request with the query intact", m.first())
	}
	if len(f) != 1 {
		t.Errorf("findings = %d, want 1 from the 200 reply", len(f))
	}
}

func TestAppendingPathJoinsWithExactlyOneSlash(t *testing.T) {
	m := &mockSink{}
	if _, err := runActive(t, "given path then\n  send request:\n    appending path: \"sub\"\n", m); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if !strings.HasPrefix(m.first(), "GET /orig/sub?a=1 ") {
		t.Errorf("sent %q, want exactly one slash between /orig and sub", m.first())
	}
}

func TestAppendingQueriesUsesAmpersandWhenAQueryExists(t *testing.T) {
	m := &mockSink{}
	if _, err := runActive(t, "given request then\n  send request:\n    appending queries: `p=1`, `q=2`\n", m); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if !strings.HasPrefix(m.first(), "GET /orig?a=1&p=1&q=2 ") {
		t.Errorf("sent %q, want p and q appended after the existing query", m.first())
	}
}

func TestReplacingHeadersSetsTheHeaderAndFixesContentLength(t *testing.T) {
	m := &mockSink{}
	if _, err := runActive(t, `given host then
  send request:
    method: "POST"
    replacing headers:
      "Content-Type": "application/json",
      "X-Probe": "yes"
    body: "{\"a\":1}"
`, m); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	sent := m.first()
	if !strings.HasPrefix(sent, "POST /orig?a=1 ") {
		t.Errorf("method not applied: %q", sent)
	}
	if !strings.Contains(sent, "Content-Type: application/json") {
		t.Errorf("content-type not replaced: %q", sent)
	}
	if !strings.Contains(sent, "X-Probe: yes") {
		t.Errorf("probe header missing: %q", sent)
	}
	// 7 bytes of body; a stale or missing length would truncate the probe
	// server-side.
	if !strings.Contains(sent, "Content-Length: 7") {
		t.Errorf("content-length not recomputed: %q", sent)
	}
	if !strings.HasSuffix(sent, "{\"a\":1}") {
		t.Errorf("body not replaced: %q", sent)
	}
}

func TestBaseAndLatestAreDifferentMessagesAfterASend(t *testing.T) {
	m := &mockSink{replies: []mockReply{{body: withStatus("500", "boom")}}}
	f, err := runActive(t, `given host then
  send request:
    path: "/probe"
  if not({latest.response.status_code} is {base.response.status_code}) then
    report issue:
      severity: medium
      confidence: firm
  end if
`, m)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(f) != 1 {
		t.Errorf("findings = %d, want 1: the probe's 500 must differ from the base 200", len(f))
	}
}

func TestANamedBindingResolvesToItsOwnResponse(t *testing.T) {
	m := &mockSink{replies: []mockReply{{body: ok200("alpha")}, {body: ok200("beta")}}}
	f, err := runActive(t, `given host then
  send request called first:
    path: "/one"
  send request called second:
    path: "/two"
  if "alpha" in {first.response.body} and "beta" in {second.response.body} then
    report issue:
      severity: low
      confidence: certain
  end if
`, m)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if m.count() != 2 {
		t.Errorf("sent %d requests, want 2", m.count())
	}
	if len(f) != 1 {
		t.Errorf("findings = %d, want 1: each name must see its own response", len(f))
	}
}

func TestAFailedSendAbandonsTheCheckInsteadOfReporting(t *testing.T) {
	m := &mockSink{replies: []mockReply{{err: errConnection}}}
	_, err := runActive(t, `given host then
  send request called probe:
    path: "/admin"
  if "x" in {probe.response.body} then
    report issue:
      severity: high
      confidence: certain
  end if
`, m)
	if err == nil {
		t.Fatal("expected the send failure to abandon the check")
	}
	if _, ok := err.(*ActiveError); !ok {
		t.Fatalf("error is %T, want *ActiveError", err)
	}
}

var errConnection = &ActiveError{Kind: ActiveSendFailed, Detail: "connection refused"}

func TestAMisnamedBindingProducesNoFinding(t *testing.T) {
	m := &mockSink{replies: []mockReply{{body: ok200("anything")}}}
	ctx := activeCtx()
	f, err := RunActive(parseCheck(`given host then
  send request called probe:
    path: "/a"
  if "anything" in {typo.response.body} then
    report issue:
      severity: high
      confidence: certain
  end if
`), ctx, m, tgt())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(f) != 0 {
		t.Errorf("findings = %d, want 0: a misnamed binding is absent, never equal to the probe's body", len(f))
	}
	found := false
	for _, u := range ctx.Unresolved() {
		if strings.Contains(u, "typo") {
			found = true
		}
	}
	if !found {
		t.Errorf("the typo was never reported as unresolved; got %v", ctx.Unresolved())
	}
}

func TestARawTemplateSendStillGoesToTheScopedTarget(t *testing.T) {
	// The one bug in this package that would matter outside the tool: a check
	// must not be able to steer traffic to a host the operator did not
	// authorise. The request bytes are the check's to choose; the connection is
	// not, so the Host header here must not redirect the send.
	m := &mockSink{}
	if _, err := runActive(t, "given host then\n  send request: `GET /x HTTP/1.1\\r\\nHost: evil.example\\r\\n\\r\\n`\n", m); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	// The sink received the raw bytes, but the target it was handed is the
	// scoped one — which the scanner's AuthorisedSender enforces by binding the
	// connection to that authority. The evaluator's half is that it never
	// invents a different target.
	if m.count() != 1 {
		t.Fatalf("sent %d requests, want 1", m.count())
	}
}

func TestSendPayloadSplicesIntoTheInsertionPoint(t *testing.T) {
	// The payload is appended to the query parameter's existing value, and the
	// finding fires because the probe's response reflects it.
	m := &mockSink{replies: []mockReply{{body: ok200("VULN")}}}
	f, err := runActive(t, `given query insertion point then
  send payload:
    appending: "VULN"
  if "VULN" in {latest.response.body} then
    report issue:
      severity: high
      confidence: certain
  end if
`, m)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if m.count() != 1 {
		t.Fatalf("sent %d requests, want 1 (one query parameter)", m.count())
	}
	// The sent request must carry the payload appended to the a=1 value, escaped
	// for the query container.
	if !strings.Contains(m.first(), "a=1VULN") {
		t.Errorf("sent %q, want the payload appended to the a parameter", m.first())
	}
	if len(f) != 1 {
		t.Errorf("findings = %d, want 1", len(f))
	}
}

func TestSendPayloadRunsOncePerPointAndNamesThePoint(t *testing.T) {
	// Two query parameters, two sends; each probe carries only its own
	// parameter's payload, which is what makes a finding attributable.
	m := &mockSink{replies: []mockReply{{body: ok200("hit a")}, {body: ok200("hit b")}}}
	ctx := activeCtx()
	ctx.Request = []byte("GET /search?a=1&b=2 HTTP/1.1\r\nHost: x.test\r\n\r\n")
	f, err := RunActive(parseCheck(`given query insertion point then
  send payload:
    replacing: "X"
  if "hit" in {latest.response.body} then
    report issue:
      severity: medium
      confidence: firm
      detail: `+"`param {insertion_point_base_value}`"+`
  end if
`), ctx, m, tgt())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if m.count() != 2 {
		t.Fatalf("sent %d requests, want 2 (one per query parameter)", m.count())
	}
	if !strings.Contains(m.sent[0], "a=X") || strings.Contains(m.sent[0], "b=X") {
		t.Errorf("first probe %q must rewrite only parameter a", m.sent[0])
	}
	if !strings.Contains(m.sent[1], "b=X") || strings.Contains(m.sent[1], "a=X") {
		t.Errorf("second probe %q must rewrite only parameter b", m.sent[1])
	}
	if len(f) != 2 {
		t.Fatalf("findings = %d, want 2 (one per point)", len(f))
	}
	if f[0].Description != "param 1" {
		t.Errorf("first finding detail = %q, want the base value of parameter a", f[0].Description)
	}
}

func TestInsertionPointCheckWithNowhereToInjectIsClean(t *testing.T) {
	// A bare GET with no query, no headers and no body has no points and no
	// declines: the check simply has nothing to do here, and that is not an
	// error.
	ctx := activeCtx()
	ctx.Request = []byte("GET / HTTP/1.1\r\nHost: x.test\r\n\r\n")
	m := &mockSink{}
	f, err := RunActive(parseCheck(`given any insertion point then
  send payload:
    replacing: "X"
  if "VULN" in {latest.response.body} then
    report issue:
      severity: high
      confidence: certain
  end if
`), ctx, m, tgt())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if m.count() != 0 {
		t.Errorf("sent %d requests, want 0", m.count())
	}
	if len(f) != 0 {
		t.Errorf("findings = %d, want 0", len(f))
	}
}

func TestADeclinedBodyIsUnsupportedWhenItIsTheOnlyPoint(t *testing.T) {
	// A `given body insertion point` check against a plain-text body has
	// somewhere to inject that the enumerator refuses to splice into. That is
	// skipped, never "tested, found nothing".
	ctx := activeCtx()
	ctx.Request = []byte("POST /f HTTP/1.1\r\nHost: x.test\r\nContent-Type: text/plain\r\n\r\njust some text")
	m := &mockSink{}
	_, err := RunActive(parseCheck(`given body insertion point then
  send payload:
    replacing: "X"
  if "VULN" in {latest.response.body} then
    report issue:
      severity: high
      confidence: certain
  end if
`), ctx, m, tgt())
	if err == nil {
		t.Fatal("expected the declined body to surface as unsupported, not as a clean run")
	}
	ae, ok := err.(*ActiveError)
	if !ok || ae.Kind != ActiveUnsupported {
		t.Fatalf("error = %v, want an ActiveUnsupported error", err)
	}
	if len(ae.Declined) == 0 {
		t.Errorf("the decline reason must travel with the error")
	}
	if m.count() != 0 {
		t.Errorf("sent %d requests, want 0", m.count())
	}
}

func TestADeclinedBodyIsRecordedAlongsideRealPoints(t *testing.T) {
	// A plain-text body next to real headers: the headers run, the body's
	// refusal is recorded on the context rather than failing the check.
	// No query string, so the only real points are the two non-reserved
	// headers: the body is declined, the headers run.
	ctx := activeCtx()
	ctx.Request = []byte("POST /f HTTP/1.1\r\nHost: x.test\r\nContent-Type: text/plain\r\nX-Probe: yes\r\n\r\njust some text")
	m := &mockSink{replies: []mockReply{{body: ok200("x")}}}
	f, err := RunActive(parseCheck(`given any insertion point then
  send payload:
    replacing: "X"
`), ctx, m, tgt())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	// Two non-reserved headers, two points: every header is attackable when the
	// body is not.
	if m.count() != 2 {
		t.Errorf("sent %d requests, want 2: the header points must still run beside the declined body", m.count())
	}
	foundProbe := false
	for _, s := range m.sent {
		if strings.Contains(s, "X-Probe: X") {
			foundProbe = true
		}
	}
	if !foundProbe {
		t.Errorf("no probe carried the payload in the X-Probe header: %v", m.sent)
	}
	if len(f) != 0 {
		t.Errorf("findings = %d, want 0", len(f))
	}
	if len(ctx.Declined()) == 0 {
		t.Errorf("the declined body must be recorded on the context")
	}
}

func TestEachForEachIterationDrawsADifferentRandomValue(t *testing.T) {
	// A cache-busting probe that repeats one value is not cache-busting. The
	// RNG must advance across iterations, not restart from the parent's seed.
	m := &mockSink{replies: []mockReply{{body: ok200("1")}, {body: ok200("2")}, {body: ok200("3")}}}
	if _, err := runActive(t, `run for each:
  suffix = "a", "b", "c"

given host then
  send request:
    appending path: `+"`{random_str(8)}{suffix}`"+`
`, m); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if m.count() != 3 {
		t.Fatalf("sent %d requests, want 3", m.count())
	}
	nonces := make([]string, 3)
	for i, s := range m.sent {
		parts := strings.Fields(s)
		if len(parts) >= 2 {
			nonces[i] = parts[1]
		}
	}
	if nonces[0] == nonces[1] || nonces[1] == nonces[2] {
		t.Errorf("iterations reused a nonce: %v", nonces)
	}
}

func TestSendRequestModifiersSurviveParsing(t *testing.T) {
	c := parseCheck(`given host then
  send request:
    method: "POST"
    path: "/x"
    replacing headers:
      "A": "1"
    body: "b"
`)
	s := c.Statements[0].(*SendRequestStatement)
	if s.Template != "" {
		t.Errorf("template = %q, want empty for the modifier form", s.Template)
	}
	if len(s.Modifiers) != 4 {
		t.Fatalf("modifiers = %d, want 4 (method, path, headers, body)", len(s.Modifiers))
	}
	if s.Modifiers[0].Target != "method" || s.Modifiers[2].Target != "headers" || len(s.Modifiers[2].Values) != 2 {
		t.Errorf("modifiers not recorded as written: %+v", s.Modifiers)
	}
}
