package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// The acceptance of burpsy-react-ui-cr37: re-send a captured request under a baseline (admin) and a
// low-priv identity; a target that returns the privileged body to the low-priv cookie is flagged
// Bypassed, and one that denies it is Enforced.
func TestAuthzTestFlagsBypassAndEnforced(t *testing.T) {
	// The target: admin cookie -> privileged body; the "leaky" path returns it to anyone, the
	// "guarded" path returns 403 to a non-admin.
	var guard string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admin := strings.Contains(r.Header.Get("Cookie"), "role=admin")
		if r.URL.Path == "/guarded" && !admin {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "denied")
			return
		}
		fmt.Fprintf(w, "SECRET admin dashboard for path %s", r.URL.Path)
	}))
	defer srv.Close()
	_ = guard
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	s := newTestServer()
	cfg := sender.DefaultSenderConfig()
	cfg.TLSVerify = false
	s.WithSender(sender.NewSender(cfg))
	s.scope.AddInclude("*")

	run := func(path string) []authzVerdict {
		raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s:%d\r\nCookie: role=admin\r\nConnection: close\r\n\r\n", path, host, port)
		reqID, _ := s.store.Put([]byte(raw), core.DirectionRequest)
		rspID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nseed"), core.DirectionResponse)
		ex := &core.Exchange{Host: host, Port: port, Method: "GET", Path: path, Request: core.MsgPtr(reqID), Response: &rspID}
		s.store.AddExchange(ex)

		if rec := putJSON(t, s, "/api/authz/identities", map[string]any{"identities": []map[string]any{
			{"label": "admin", "baseline": true, "cookie": "role=admin"},
			{"label": "low-priv", "cookie": "role=user"},
		}}); rec.Code != http.StatusOK {
			t.Fatalf("PUT identities = %d: %s", rec.Code, rec.Body.String())
		}
		rec := postJSON(t, s, "/api/authz/test", map[string]any{"exchange_id": uint64(ex.ID), "samples": 3})
		if rec.Code != http.StatusOK {
			t.Fatalf("POST test = %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Verdicts []authzVerdict `json:"verdicts"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.Verdicts
	}

	// Leaky path: the low-priv cookie still gets the admin body -> Bypassed.
	leaky := run("/leak")
	lp := verdictFor(t, leaky, "low-priv")
	if lp.Verdict != "Bypassed" {
		t.Errorf("leaky path low-priv verdict = %q, want Bypassed (reasons %v)", lp.Verdict, lp.Reasons)
	}
	if lp.ResponseID == nil {
		t.Error("a verdict must carry a response id for the Comparer diff")
	}
	if verdictFor(t, leaky, "admin").Verdict != "Baseline" {
		t.Error("the baseline identity must be labelled Baseline")
	}

	// Guarded path: the low-priv cookie is denied (403, different body) -> Enforced.
	guarded := run("/guarded")
	if gp := verdictFor(t, guarded, "low-priv"); gp.Verdict != "Enforced" {
		t.Errorf("guarded path low-priv verdict = %q, want Enforced (status %d reasons %v)", gp.Verdict, gp.Status, gp.Reasons)
	}
}

func verdictFor(t *testing.T, vs []authzVerdict, label string) authzVerdict {
	t.Helper()
	for _, v := range vs {
		if v.Label == label {
			return v
		}
	}
	t.Fatalf("no verdict for %q", label)
	return authzVerdict{}
}

// Identities are validated and saved with the project: exactly one baseline, unique labels.
func TestAuthzIdentitiesValidation(t *testing.T) {
	s := newTestServer()
	if rec := putJSON(t, s, "/api/authz/identities", map[string]any{"identities": []map[string]any{
		{"label": "a", "baseline": true}, {"label": "a"},
	}}); rec.Code != http.StatusBadRequest {
		t.Errorf("duplicate label = %d, want 400", rec.Code)
	}
	if rec := putJSON(t, s, "/api/authz/identities", map[string]any{"identities": []map[string]any{
		{"label": "a"}, {"label": "b"},
	}}); rec.Code != http.StatusBadRequest {
		t.Errorf("no baseline = %d, want 400", rec.Code)
	}
	if rec := postJSON(t, s, "/api/authz/test", map[string]any{"exchange_id": 1}); rec.Code != http.StatusBadRequest {
		t.Errorf("test with <2 identities = %d, want 400", rec.Code)
	}
}
