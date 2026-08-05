package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// The attack this closes: the operator excludes /admin on an otherwise in-scope host, then
// retypes a Repeater request's path to /admin by hand. handleRepeaterSend does not parse the
// request line at all, so the only thing that can catch this is AuthoriseRaw running on the
// exact bytes about to be sent — the same gate the intruder handler already used. Before this
// fix, MayContainHost was the only check, and it deliberately reports "possible" for a
// path-scoped exclude (core/scope.go), so this request went straight out.
func TestRepeaterRefusesARequestWhosePathIsExcludedFromScope(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	host, port, _, err := targetParts(target.URL[len("http://"):])
	if err != nil {
		t.Fatal(err)
	}

	scope := core.NewScope()
	scope.AddInclude(host)
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, host, "/admin"))

	s := NewServer(core.NewTrafficStore(), scope)
	s.WithSender(sender.NewSender(sender.DefaultSenderConfig()))

	req := repeaterSendReq{
		Target:  fmt.Sprintf("%s:%d", host, port),
		Request: "GET /admin HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n",
	}
	body, _ := json.Marshal(req)
	rec := httptest.NewRecorder()
	s.handleRepeaterSend(rec, httptest.NewRequest(http.MethodPost, "/api/repeater/send", bytes.NewReader(body)))

	if rec.Code != http.StatusBadGateway && rec.Code != http.StatusForbidden {
		t.Fatalf("want the request refused, got %d: %s", rec.Code, rec.Body.String())
	}
	if hits != 0 {
		t.Fatalf("a path-excluded request must never reach the target, but it was hit %d time(s)", hits)
	}
}

// The positive control: an in-scope path is still sent, so this is a scope check and not a
// blanket refusal of everything the AuthorisedSender wraps.
func TestRepeaterSendsARequestWhosePathIsInScope(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	host, port, _, err := targetParts(target.URL[len("http://"):])
	if err != nil {
		t.Fatal(err)
	}

	scope := core.NewScope()
	scope.AddInclude(host)
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, host, "/admin"))

	s := NewServer(core.NewTrafficStore(), scope)
	s.WithSender(sender.NewSender(sender.DefaultSenderConfig()))

	req := repeaterSendReq{
		Target:  fmt.Sprintf("%s:%d", host, port),
		Request: "GET /ok HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n",
	}
	body, _ := json.Marshal(req)
	rec := httptest.NewRecorder()
	s.handleRepeaterSend(rec, httptest.NewRequest(http.MethodPost, "/api/repeater/send", bytes.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 for an in-scope send, got %d: %s", rec.Code, rec.Body.String())
	}
	if hits != 1 {
		t.Fatalf("want exactly one hit, got %d", hits)
	}
}
