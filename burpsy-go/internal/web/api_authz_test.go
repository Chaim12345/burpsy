package web

import (
	"compress/gzip"
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

// runAuthzTest stores one captured request for method+path against host:port, saves identities, runs
// POST /api/authz/test with three calibration samples and returns the verdicts.
func runAuthzTest(t *testing.T, s *Server, method, path, host string, port uint16, identities []map[string]any) []authzVerdict {
	t.Helper()
	raw := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s:%d\r\nCookie: role=admin\r\nAccept-Encoding: gzip\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", method, path, host, port)
	reqID, _ := s.store.Put([]byte(raw), core.DirectionRequest)
	rspID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nseed"), core.DirectionResponse)
	ex := &core.Exchange{Host: host, Port: port, Method: method, Path: path, Request: core.MsgPtr(reqID), Response: &rspID}
	s.store.AddExchange(ex)
	if rec := putJSON(t, s, "/api/authz/identities", map[string]any{"identities": identities}); rec.Code != http.StatusOK {
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

// The two false-positive shapes from a live run (52 endpoints x 8 identities). A baseline that was
// itself refused (400/403/500) inverted every verdict: an identity refused the same way "matched" it and
// was called Bypassed, and one that got a 200 "differed" and was called Enforced. A baseline served an
// empty collection made every role's identical empty answer a Bypassed. Both are now Ambiguous, with a
// reason that says what to change, and only on a read for the empty case: a write acknowledged
// identically for every role is the function-level bypass and stays Bypassed.
func TestAuthzVerdictIsAmbiguousWhenTheBaselineIsNoReference(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := r.Header.Get("Cookie")
		switch r.URL.Path {
		case "/refused": // the baseline (admin) is refused; a viewer is served
			if strings.Contains(role, "role=viewer") {
				fmt.Fprint(w, `{"jobs":[{"id":1}]}`)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "forbidden")
		case "/broken": // the baseline's request fails server-side for everyone
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "internal error")
		case "/jobs": // an empty job list for every role, gzip-encoded and chunked as Express sends it
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write([]byte(`{"rows":[],`))
			_ = zw.Flush()
			w.(http.Flusher).Flush()
			_, _ = zw.Write([]byte(`"count":0}`))
			_ = zw.Close()
		}
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	s := newTestServer()
	cfg := sender.DefaultSenderConfig()
	cfg.TLSVerify = false
	s.WithSender(sender.NewSender(cfg))
	s.scope.AddInclude("*")
	identities := []map[string]any{
		{"label": "admin", "baseline": true, "cookie": "role=admin"},
		{"label": "low-priv", "cookie": "role=user"},
		{"label": "viewer", "cookie": "role=viewer"},
	}

	for _, tc := range []struct{ path, status string }{{"/refused", "status 403"}, {"/broken", "status 500"}} {
		vs := runAuthzTest(t, s, "GET", tc.path, host, port, identities)
		for _, label := range []string{"low-priv", "viewer"} {
			v := verdictFor(t, vs, label)
			if v.Verdict != "Ambiguous" || len(v.Reasons) == 0 ||
				!strings.Contains(v.Reasons[0], tc.status) || !strings.Contains(v.Reasons[0], "pick a privileged baseline") {
				t.Errorf("%s %s: verdict %q reasons %v; want Ambiguous because the baseline was not authorised (%s)",
					tc.path, label, v.Verdict, v.Reasons, tc.status)
			}
		}
	}

	vs := runAuthzTest(t, s, "GET", "/jobs", host, port, identities)
	for _, label := range []string{"low-priv", "viewer"} {
		v := verdictFor(t, vs, label)
		if v.Verdict != "Ambiguous" || len(v.Reasons) == 0 || v.Reasons[0] != "baseline returned no data; seed data the baseline can see" {
			t.Errorf("GET /jobs %s: verdict %q reasons %v; an empty list for every role is no evidence of a bypass", label, v.Verdict, v.Reasons)
		}
	}

	vs = runAuthzTest(t, s, "POST", "/jobs", host, port, identities)
	if v := verdictFor(t, vs, "low-priv"); v.Verdict != "Bypassed" {
		t.Errorf("POST /jobs low-priv: verdict %q reasons %v; a write answered identically for every role is a bypass", v.Verdict, v.Reasons)
	}
}
