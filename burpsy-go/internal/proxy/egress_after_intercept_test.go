package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"go.uber.org/zap"
)

// The Miscellaneous request knobs must run AFTER the intercept hold (burpsy-react-ui-6keo).
//
// ApplyRequestEgress sat above the hold, under a comment claiming it ran after it. With "strip
// Proxy-* headers" seeded ON, a held request had already lost its Proxy-Authorization by the time
// the operator saw it: they could not read what the client sent, could not decide about it, and
// could not restore it. Intercept exists to show the client's real bytes, and a transform applied
// before the hold is both invisible and unrecoverable.
//
// This asserts the two halves that matter: the operator sees the header, and the origin does not.

func TestAHeldRequestStillCarriesTheHeadersEgressWillStrip(t *testing.T) {
	var originSawProxyHeader atomic.Bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			originSawProxyHeader.Store(true)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()
	ohost, oportStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	oport, _ := strconv.Atoi(oportStr)

	// An empty rule list on an active list is Burp's "intercept everything", which keeps this test
	// about the ordering rather than about rule matching.
	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	if err := engine.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}

	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(core.NewScope()).
		WithIntercept(engine).
		WithLogger(zap.NewNop()))

	// The operator: take whatever is held, record what they were shown, and forward it unchanged.
	var heldRequest atomic.Value
	heldRequest.Store("")
	go func() {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			for _, held := range engine.Held() {
				if held.Direction != intercept.DirectionRequest {
					continue
				}
				// Recorded exactly as the operator would read it, then forwarded unchanged: the
				// subject is what they were shown, not what they could do to it.
				heldRequest.Store(string(held.Raw))
				_ = engine.Forward(held.ID, nil, false, nil)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()

	// A raw request through the proxy carrying the header the knob strips.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	req := "GET http://" + ohost + ":" + strconv.Itoa(oport) + "/ HTTP/1.1\r\n" +
		"Host: " + ohost + ":" + strconv.Itoa(oport) + "\r\n" +
		"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read response: %v", err)
	}

	held, _ := heldRequest.Load().(string)
	if held == "" {
		t.Fatal("nothing was held, so this proves nothing about what the operator would have seen")
	}
	if !strings.Contains(held, "Proxy-Authorization") {
		t.Errorf("the held request had already been stripped:\n%s", held)
	}
	// And the knob still does its job on the way out — a fix that simply stopped stripping would
	// pass the assertion above.
	if originSawProxyHeader.Load() {
		t.Error("the origin received Proxy-Authorization; the strip knob is seeded on and must still apply")
	}
}
