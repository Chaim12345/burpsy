package web

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// burpsy-react-ui-vuxy: the structured Repeater send — derive from a stored request, edit with ops,
// preview with dry_run, pin the HTTP version.

// rawOrigin is a TCP origin that records the exact bytes of each request it receives.
type rawOrigin struct {
	ln   net.Listener
	mu   sync.Mutex
	seen [][]byte
}

func newRawOrigin(t *testing.T) *rawOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &rawOrigin{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go o.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return o
}

func (o *rawOrigin) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	var head bytes.Buffer
	length := 0
	for {
		line, err := br.ReadBytes('\n')
		head.Write(line)
		if err != nil {
			return
		}
		if l := strings.TrimSpace(string(line)); strings.HasPrefix(strings.ToLower(l), "content-length:") {
			length, _ = strconv.Atoi(strings.TrimSpace(l[len("content-length:"):]))
		}
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			break
		}
	}
	body := make([]byte, length)
	io.ReadFull(br, body)
	o.mu.Lock()
	o.seen = append(o.seen, append(head.Bytes(), body...))
	o.mu.Unlock()
	c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
}

func (o *rawOrigin) last() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.seen) == 0 {
		return nil
	}
	return o.seen[len(o.seen)-1]
}

// captureExchange stores a request as a proxied exchange to o and returns the exchange and message ids.
func captureForEdit(t *testing.T, s *Server, o *rawOrigin, raw string) (core.ExchangeID, core.MsgId) {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(o.ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	id, err := s.store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	s.store.AddExchange(&core.Exchange{Request: core.MsgPtr(id), Host: host, Port: uint16(port), Method: "POST", Path: "/api/users", Source: core.SourceProxy})
	all := s.store.Exchanges()
	return all[len(all)-1].ID, id
}

const capturedReq = "POST /api/users?id=7 HTTP/1.1\r\nHost: shop.test\r\nCookie: sess=abc\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"role\":\"viewer\"}\n"

func TestTheTargetReceivesExactlyTheDryRunBytes(t *testing.T) {
	o := newRawOrigin(t)
	s := newTestServer()
	exID, msgID := captureForEdit(t, s, o, capturedReq)
	body := map[string]any{
		"from_exchange": exID,
		"edits": []map[string]any{
			{"op": "set_query_param", "name": "id", "value": "8"},
			{"op": "set_request_cookie", "name": "sess", "value": "stolen"},
			{"op": "set_json_field", "name": "role", "value": `"admin"`},
		},
		"dry_run": true,
	}
	rec := postJSON(t, s, "/api/repeater/send", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("dry run = %d: %s", rec.Code, rec.Body.String())
	}
	var preview struct {
		DryRun        bool   `json:"dry_run"`
		Request       string `json:"request"`
		RequestBase64 string `json:"request_base64"`
		EditsApplied  []any  `json:"edits_applied"`
		Scope         struct {
			Allowed bool `json:"allowed"`
		} `json:"scope"`
	}
	json.Unmarshal(rec.Body.Bytes(), &preview)
	want := "POST /api/users?id=8 HTTP/1.1\r\nHost: shop.test\r\nCookie: sess=stolen\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"role\":\"admin\"}\n"
	if !preview.DryRun || preview.Request != want || !preview.Scope.Allowed || len(preview.EditsApplied) != 4 {
		t.Fatalf("preview wrong:\n%s", rec.Body.String())
	}
	if o.last() != nil {
		t.Fatal("a dry run sent a request")
	}

	// The same call without dry_run: the origin receives exactly the previewed bytes.
	delete(body, "dry_run")
	rec = postJSON(t, s, "/api/repeater/send", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("send = %d: %s", rec.Code, rec.Body.String())
	}
	exact, _ := base64.StdEncoding.DecodeString(preview.RequestBase64)
	if got := o.last(); !bytes.Equal(got, exact) {
		t.Fatalf("the origin received\n%q\nthe preview promised\n%q", got, exact)
	}
	var sent struct {
		RequestMsgID uint64 `json:"request_msg_id"`
		ExchangeID   uint64 `json:"exchange_id"`
		EditsApplied []any  `json:"edits_applied"`
	}
	json.Unmarshal(rec.Body.Bytes(), &sent)
	if len(sent.EditsApplied) != 4 {
		t.Fatalf("the send does not report its edits: %s", rec.Body.String())
	}
	// Fork on edit: the base is untouched, the edited request is a new message, the exchange's parent is the base.
	if m, _ := s.store.Get(msgID); string(m.Raw()) != capturedReq {
		t.Fatal("the stored base request was modified")
	}
	if m, _ := s.store.Get(core.MsgId(sent.RequestMsgID)); string(m.Raw()) != want {
		t.Fatalf("the stored edited request is %q", m.Raw())
	}
	ex, _ := s.store.GetExchange(core.ExchangeID(sent.ExchangeID))
	if ex.ParentID == nil || *ex.ParentID != exID {
		t.Fatalf("the edited send's parent is %v, want %d", ex.ParentID, exID)
	}

	// from_message derives the same base (and the target) from the message id alone.
	rec = postJSON(t, s, "/api/repeater/send", map[string]any{"from_message": msgID, "dry_run": true})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"request":"POST /api/users?id=7`) {
		t.Fatalf("from_message dry run = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAnEditIntoAPathScopedExcludeIsRefusedOnTheEditedBytes(t *testing.T) {
	o := newRawOrigin(t)
	s := newTestServer()
	exID, _ := captureForEdit(t, s, o, capturedReq)
	host, _, _ := net.SplitHostPort(o.ln.Addr().String())
	admin := "/admin"
	inc, _ := core.NewScopeRuleFrom(core.ScopeInclude, host, nil, nil, nil)
	exc, _ := core.NewScopeRuleFrom(core.ScopeExclude, host, &admin, nil, nil)
	s.scope.Add(inc)
	s.scope.Add(exc)
	body := map[string]any{"from_exchange": exID, "edits": []map[string]any{{"op": "set_path", "value": "/admin/delete"}}}

	body["dry_run"] = true
	rec := postJSON(t, s, "/api/repeater/send", body)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"allowed":false`) {
		t.Fatalf("the dry run did not report the refusal: %d %s", rec.Code, rec.Body.String())
	}
	delete(body, "dry_run")
	rec = postJSON(t, s, "/api/repeater/send", body)
	if rec.Code != http.StatusForbidden || o.last() != nil {
		t.Fatalf("an edit into an excluded path was sent: %d %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPVersionTwoForcesH2(t *testing.T) {
	var proto string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	cfg := sender.DefaultSenderConfig()
	cfg.TLSVerify = false // the test origin's certificate is self-signed
	s := newTestServer()
	s.WithSender(sender.NewSender(cfg))
	authority := strings.TrimPrefix(srv.URL, "https://")
	raw := "GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"
	for _, c := range []struct{ version, want string }{{"1.1", "HTTP/1.1"}, {"2", "HTTP/2.0"}} {
		proto = ""
		rec := postJSON(t, s, "/api/repeater/send", map[string]any{"target": "https://" + authority, "request": raw, "http_version": c.version})
		if rec.Code != http.StatusOK || proto != c.want {
			t.Fatalf("http_version %s: %d, origin saw %q: %s", c.version, rec.Code, proto, rec.Body.String())
		}
	}
	rec := postJSON(t, s, "/api/repeater/send", map[string]any{"target": "https://" + authority, "request": raw, "http_version": "3"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("http_version 3 answered %d", rec.Code)
	}
	rec = postJSON(t, s, "/api/repeater/send", map[string]any{"target": "https://" + authority, "request": raw, "http_version": "2", "options": map[string]any{"protocol_preference": "http1"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a contradictory pin answered %d", rec.Code)
	}
}

func TestStructuredSendRefusals(t *testing.T) {
	s := newTestServer()
	for _, b := range []map[string]any{
		{"from_message": 999, "dry_run": true},
		{"from_exchange": 999},
		{"request": "GET / HTTP/1.1\r\nHost: a\r\n\r\n", "target": "a:80", "edits": []map[string]any{{"op": "explode"}}},
		{"edits": []map[string]any{{"op": "set_method", "value": "GET"}}},
	} {
		rec := postJSON(t, s, "/api/repeater/send", b)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%v answered %d: %s", b, rec.Code, rec.Body.String())
		}
	}
	_ = fmt.Sprint
}
