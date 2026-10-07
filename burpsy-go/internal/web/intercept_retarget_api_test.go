package web

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/intercept"
)

// Burp's "Edit target" reaches the proxy through the forward body (burpsy-react-ui-akv):
// POST /api/intercept/{id}/forward carries host, port and tls alongside the edited bytes.

// holdOneRequest holds a single request through the server's engine and returns it.
func holdOneRequest(t *testing.T, s *Server, host string, port uint16, tls bool) *intercept.Held {
	t.Helper()
	s.intercept.SetEnabled(true)
	if err := s.intercept.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	h := s.intercept.Hold(&intercept.Message{
		Direction: intercept.DirectionRequest, Host: host, Port: port, TLS: tls,
		Method: "GET", Path: "/cart",
		Raw: []byte("GET /cart HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
	})
	if h == nil {
		t.Fatal("request not held: enable the engine or drop the unconditional assumption")
	}
	return h
}

// TestForwardCarriesATargetTheEngineReportsBack: the whole point of the wire field. The engine is
// what the proxy asks, so the assertion is made through Wait rather than against a field the API
// might have set and the proxy never read.
func TestForwardCarriesATargetTheEngineReportsBack(t *testing.T) {
	s := newTestServer()
	h := holdOneRequest(t, s, "shop.internal", 443, true)

	done := make(chan *intercept.Target, 1)
	go func() {
		_, _, target, _ := h.Wait()
		done <- target
	}()

	rec := postJSON(t, s, "/api/intercept/"+strconv.FormatUint(h.ID, 10)+"/forward", map[string]any{
		"host": "other.internal",
		"port": 8443,
		"tls":  false,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("forward: status = %d (%s)", rec.Code, rec.Body.String())
	}

	select {
	case target := <-done:
		if target == nil {
			t.Fatal("the retarget did not reach the engine, so the proxy would send the request to the original host")
		}
		if target.Host != "other.internal" || target.Port != 8443 || target.TLS {
			t.Errorf("target = %+v, want other.internal:8443 plaintext", *target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait never returned after a successful forward")
	}
}

// TestForwardRefusesAPartialTarget: the three fields describe one destination, so filling the
// omissions in from the held message would invent a destination the operator never typed — a caller
// sending only the port would silently inherit the old host, which is the most dangerous of the two
// possible completions.
func TestForwardRefusesAPartialTarget(t *testing.T) {
	for _, body := range []map[string]any{
		{"port": 8443, "tls": false},
		{"host": "other.internal", "tls": false},
		{"host": "other.internal", "port": 8443},
	} {
		s := newTestServer()
		h := holdOneRequest(t, s, "shop.internal", 443, true)
		rec := postJSON(t, s, "/api/intercept/"+strconv.FormatUint(h.ID, 10)+"/forward", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("forward with only %v: status = %d, want 400", body, rec.Code)
		}
		// The hold must survive a refused destination: resolving it would send the request to the
		// original host, which is the opposite of what the operator asked for.
		if rec := postJSON(t, s, "/api/intercept/"+strconv.FormatUint(h.ID, 10)+"/drop", map[string]any{"reason": "cleanup"}); rec.Code != http.StatusOK {
			t.Errorf("drop after a refused forward: status = %d, want the hold to still exist", rec.Code)
		}
	}
}

// TestForwardWithoutATargetIsUnchanged: every existing caller sends no destination, and that has to
// keep meaning "send it where the client asked".
func TestForwardWithoutATargetIsUnchanged(t *testing.T) {
	s := newTestServer()
	h := holdOneRequest(t, s, "shop.internal", 443, true)

	done := make(chan *intercept.Target, 1)
	go func() {
		_, _, target, _ := h.Wait()
		done <- target
	}()
	if rec := postJSON(t, s, "/api/intercept/"+strconv.FormatUint(h.ID, 10)+"/forward", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("forward: status = %d (%s)", rec.Code, rec.Body.String())
	}
	select {
	case target := <-done:
		if target != nil {
			t.Errorf("a forward with no destination produced %+v", *target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait never returned")
	}
}

// TestForwardRefusesARetargetWithNoHost: refused by the engine, and reported as the caller's mistake
// about the request rather than as a missing item — 400 rather than 404, so the console shows the
// reason instead of "no such item".
func TestForwardRefusesARetargetWithNoHost(t *testing.T) {
	s := newTestServer()
	h := holdOneRequest(t, s, "shop.internal", 443, true)
	rec := postJSON(t, s, "/api/intercept/"+strconv.FormatUint(h.ID, 10)+"/forward", map[string]any{
		"host": "   ",
		"port": 8443,
		"tls":  false,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}
