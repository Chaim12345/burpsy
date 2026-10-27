package sender

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// hookTestScope authorises everything except bytes carrying refuseSub, so a test can make one
// specific replacement out of scope.
type hookTestScope struct{ refuseSub string }

func (s hookTestScope) AuthoriseRaw(host string, port uint16, tls bool, raw []byte) error {
	if s.refuseSub != "" && strings.Contains(string(raw), s.refuseSub) {
		return fmt.Errorf("refused: carries %q", s.refuseSub)
	}
	return nil
}

// hookServer records the last request body it received and answers 200 "hello".
func hookServer(t *testing.T, seen *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		seen.Store(string(buf))
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sendOne(t *testing.T, snd *Sender, srv *httptest.Server, scope ScopeChecker, body string) (AuthorisedResult, error) {
	t.Helper()
	host, port, err := hostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("hostPort: %v", err)
	}
	raw := []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", srv.Listener.Addr().String(), len(body), body))
	a := NewAuthorisedSender(scope, snd, host, port, false)
	return a.Send(context.Background(), raw)
}

func TestHTTPHookRequestReplacementReachesTheWire(t *testing.T) {
	var seen atomic.Value
	srv := hookServer(t, &seen)
	snd := NewSender(DefaultSenderConfig()).WithHTTPHook(HTTPHookFunc(func(_ context.Context, phase string, raw []byte) HTTPHookResult {
		if phase != "request" {
			return HTTPHookResult{Raw: raw}
		}
		return HTTPHookResult{Raw: []byte(strings.Replace(string(raw), "original", "replaced", 1)), Changed: true, Applied: []string{"p1"}}
	}))
	res, err := sendOne(t, snd, srv, hookTestScope{}, "original")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := seen.Load().(string); !strings.Contains(got, "replaced") {
		t.Fatalf("wire carries %q, want the replacement", got)
	}
	if res.Status == nil || *res.Status != 200 {
		t.Fatalf("status %d", res.Status)
	}
	if c := snd.HTTPHookCounts(); c.RequestsChanged != 1 {
		t.Fatalf("counters %+v, want RequestsChanged=1", c)
	}
}

func TestHTTPHookReplacementMustPassScopeAgain(t *testing.T) {
	var seen atomic.Value
	srv := hookServer(t, &seen)
	snd := NewSender(DefaultSenderConfig()).WithHTTPHook(HTTPHookFunc(func(_ context.Context, phase string, raw []byte) HTTPHookResult {
		if phase != "request" {
			return HTTPHookResult{Raw: raw}
		}
		return HTTPHookResult{Raw: []byte(strings.Replace(string(raw), "original", "forbidden-token", 1)), Changed: true, Applied: []string{"p1"}}
	}))
	_, err := sendOne(t, snd, srv, hookTestScope{refuseSub: "forbidden-token"}, "original")
	if err == nil || !strings.Contains(err.Error(), "forbidden-token") {
		t.Fatalf("err %v, want the scope refusal of the replacement", err)
	}
	if seen.Load() != nil {
		t.Fatalf("a byte reached the wire for a scope-refused replacement: %q", seen.Load())
	}
}

func TestHTTPHookResponseReplacementIsWhatTheCallerSees(t *testing.T) {
	var seen atomic.Value
	srv := hookServer(t, &seen)
	snd := NewSender(DefaultSenderConfig()).WithHTTPHook(HTTPHookFunc(func(_ context.Context, phase string, raw []byte) HTTPHookResult {
		if phase != "response" {
			return HTTPHookResult{Raw: raw}
		}
		return HTTPHookResult{Raw: []byte(strings.Replace(string(raw), "hello", "hooked", 1)), Changed: true, Applied: []string{"p1"}}
	}))
	res, err := sendOne(t, snd, srv, hookTestScope{}, "x")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !strings.Contains(string(res.Raw), "hooked") {
		t.Fatalf("caller sees %q, want the hooked response", res.Raw)
	}
	if c := snd.HTTPHookCounts(); c.ResponsesChanged != 1 {
		t.Fatalf("counters %+v, want ResponsesChanged=1", c)
	}
}

func TestHTTPHookFailuresNeverBlockAndAreCounted(t *testing.T) {
	var seen atomic.Value
	srv := hookServer(t, &seen)
	snd := NewSender(DefaultSenderConfig()).WithHTTPHook(HTTPHookFunc(func(_ context.Context, _ string, raw []byte) HTTPHookResult {
		return HTTPHookResult{Raw: raw, Failures: 2} // host-style: original bytes, failures noted
	}))
	if _, err := sendOne(t, snd, srv, hookTestScope{}, "x"); err != nil {
		t.Fatalf("send with failing plugin must succeed: %v", err)
	}
	// request + response both offered, two failures each
	if c := snd.HTTPHookCounts(); c.Failures != 4 {
		t.Fatalf("counters %+v, want Failures=4", c)
	}
}

func TestNoHookIsByteIdentical(t *testing.T) {
	var seen atomic.Value
	srv := hookServer(t, &seen)
	snd := NewSender(DefaultSenderConfig())
	res, err := sendOne(t, snd, srv, hookTestScope{}, "untouched")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := seen.Load().(string); got != "untouched" {
		t.Fatalf("wire carries %q without a hook", got)
	}
	if !strings.Contains(string(res.Raw), "hello") {
		t.Fatalf("response %q without a hook", res.Raw)
	}
	if c := snd.HTTPHookCounts(); c != (HTTPHookCounters{}) {
		t.Fatalf("counters %+v without a hook, want zero", c)
	}
}
