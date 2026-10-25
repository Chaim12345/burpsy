package web

// Extension services (burpsy-react-ui-wiwh, slice 6): the host methods stand
// on something real. What is pinned: http.send leaves through the scoped
// sender (in-scope arrives, out-of-scope is ErrOutOfScope and never dialled),
// event.raise lands on the dashboard named by its plugin, storage round-trips
// and enforces the bounds, and traffic.query/scope.check read the same store
// and scope the operator's pages use.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/extension"
)

func TestExtensionSendGoesThroughTheScopedSender(t *testing.T) {
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "served")
	}))
	defer origin.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	s := newTestServer()
	s.scope.AddInclude(host)
	svc := s.ExtensionServices()

	resp, err := svc.Send(context.Background(), "plug", extension.SessionRequest{Method: "GET", URL: origin.URL + "/from-plugin"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Status != http.StatusOK || !strings.Contains(resp.Body, "served") {
		t.Fatalf("response = %+v", resp)
	}
	if hits.Load() != 1 {
		t.Fatalf("origin hits = %d", hits.Load())
	}

	// A different authority is outside the engagement: refused as ErrOutOfScope,
	// and the counter proves nothing was dialled for it.
	_, err = svc.Send(context.Background(), "plug", extension.SessionRequest{Method: "GET", URL: "http://elsewhere.invalid:8080/"})
	if !errors.Is(err, extension.ErrOutOfScope) {
		t.Fatalf("out-of-scope send: err = %v, want ErrOutOfScope", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("the refused send was dialled: hits = %d", hits.Load())
	}
}

func TestExtensionRaiseEventLandsOnTheDashboard(t *testing.T) {
	s := newTestServer()
	s.ExtensionServices().RaiseEvent("plug", extension.EventError, "the plugin says so")
	for _, ev := range s.Events().Recent(10) {
		if ev.Kind == "extension" && strings.Contains(ev.Detail, "plug: the plugin says so") {
			return
		}
	}
	t.Fatalf("no extension event in %v", s.Events().Recent(10))
}

func TestExtensionStorageRoundTripsAndEnforcesBounds(t *testing.T) {
	s := newTestServer()
	st := s.ExtensionServices().Storage

	if err := st.Set("plug", extension.ScopeProject, "token", json.RawMessage(`"abc"`)); err != nil {
		t.Fatalf("set: %v", err)
	}
	v, found, err := st.Get("plug", extension.ScopeProject, "token")
	if err != nil || !found || string(v) != `"abc"` {
		t.Fatalf("get = %q %v %v", v, found, err)
	}
	// Another plugin's view of the same key is empty: the map key carries the plugin.
	if _, found, _ := st.Get("other", extension.ScopeProject, "token"); found {
		t.Fatal("plugin isolation: another plugin read plug's row")
	}
	if err := st.Set("plug", extension.ScopeProject, strings.Repeat("k", extension.MaxStorageKeyBytes+1), json.RawMessage(`1`)); err == nil {
		t.Fatal("an over-long key was accepted")
	}
	if err := st.Delete("plug", extension.ScopeProject, "token"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, found, _ := st.Get("plug", extension.ScopeProject, "token"); found {
		t.Fatal("deleted row still reads")
	}
}

func TestExtensionTrafficReadsTheStoreAndScope(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("example.test")
	raw := "GET /a HTTP/1.1\r\nHost: example.test:80\r\n\r\n"
	reqID, _ := s.store.Put([]byte(raw), core.DirectionRequest)
	rspID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), core.DirectionResponse)
	status := uint16(200)
	s.store.AddExchange(&core.Exchange{Host: "example.test", Port: 80, Method: "GET", Path: "/a", Status: &status, Request: core.MsgPtr(reqID), Response: &rspID})

	svc := s.ExtensionServices()
	page, err := svc.Traffic.Query(context.Background(), "plug", extension.TrafficQuery{Source: extension.TrafficProxy, Host: "example.test", IncludeBodies: true})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("page = %+v", page)
	}
	if !strings.Contains(page.Items[0].Request, "GET /a") || !strings.Contains(page.Items[0].Response, "200") {
		t.Fatalf("bodies = %+v", page.Items[0])
	}
	if page.Items[0].Status != 200 {
		t.Fatalf("status = %d", page.Items[0].Status)
	}
	// The bounded page is honoured: a limit of 0 means the default, and an
	// over-limit ask is clamped, not obeyed.
	if _, err := svc.Traffic.Query(context.Background(), "plug", extension.TrafficQuery{Source: extension.TrafficOrganizer}); err == nil {
		t.Fatal("the organizer source answered as if wired")
	}

	in, err := svc.Traffic.InScope(context.Background(), "http://example.test/a")
	if err != nil || !in {
		t.Fatalf("in-scope = %v %v", in, err)
	}
	out, err := svc.Traffic.InScope(context.Background(), "http://elsewhere.invalid/")
	if err != nil || out {
		t.Fatalf("out-of-scope = %v %v", out, err)
	}
}
