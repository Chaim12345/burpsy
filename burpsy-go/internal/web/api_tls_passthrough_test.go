package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/proxy"
)

// ---- The TLS passthrough runtime surface ----------------------------------------
//
// The engine could always skip interception for listed hosts, but the only way to
// edit the list was a startup flag, so a mistake meant restarting the proxy in the
// middle of an engagement. These tests pin the wire behaviour the Settings page
// depends on: add appends, remove takes back exactly the rule named, removing a
// rule that is not there says so instead of silently succeeding, and a server with
// no policy attached admits it rather than serving a fake empty list.

func newPassthroughTestServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(core.NewTrafficStore(), core.NewScope()).
		WithTlsPolicy(proxy.NewTlsPolicy())
}

func getJSON(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func deleteJSON(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func decodePatterns(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	var view struct {
		Patterns []string `json:"patterns"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return view.Patterns
}

func TestPassthroughEndpointsAddAndRemoveExactPatterns(t *testing.T) {
	s := newPassthroughTestServer(t)

	if rec := postJSON(t, s, "/api/proxy/passthrough", map[string]string{"pattern": "*.bank.test"}); rec.Code != http.StatusOK {
		t.Fatalf("add *.bank.test: status = %d, body %s", rec.Code, rec.Body.String())
	}
	if rec := postJSON(t, s, "/api/proxy/passthrough", map[string]string{"pattern": "safe.test"}); rec.Code != http.StatusOK {
		t.Fatalf("add safe.test: status = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := decodePatterns(t, getJSON(t, s, "/api/proxy/passthrough")); len(got) != 2 {
		t.Fatalf("patterns = %v; both adds must be visible to the next reader", got)
	}

	del := deleteJSON(t, s, "/api/proxy/passthrough?pattern="+url.QueryEscape("*.bank.test"))
	if del.Code != http.StatusOK {
		t.Fatalf("remove *.bank.test: status = %d, body %s", del.Code, del.Body.String())
	}
	got := decodePatterns(t, getJSON(t, s, "/api/proxy/passthrough"))
	if len(got) != 1 || got[0] != "safe.test" {
		t.Fatalf("patterns = %v; exact-match removal must leave the sibling rule standing", got)
	}
}

func TestPassthroughRemoveOfAnAbsentPatternIsHonestNotFound(t *testing.T) {
	s := newPassthroughTestServer(t)
	postJSON(t, s, "/api/proxy/passthrough", map[string]string{"pattern": "safe.test"})

	del := deleteJSON(t, s, "/api/proxy/passthrough?pattern=never.added.test")
	if del.Code != http.StatusNotFound {
		t.Fatalf("status = %d; removing a rule that was never added must say so, not report success", del.Code)
	}
	if got := decodePatterns(t, getJSON(t, s, "/api/proxy/passthrough")); len(got) != 1 || got[0] != "safe.test" {
		t.Fatalf("patterns = %v; a refused removal must not disturb the list", got)
	}
}

func TestPassthroughPostWithAnEmptyPatternIsRefused(t *testing.T) {
	s := newPassthroughTestServer(t)

	for _, bad := range []string{"", "   "} {
		rec := postJSON(t, s, "/api/proxy/passthrough", map[string]string{"pattern": bad})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("pattern %q: status = %d; a blank rule must be refused, not stored", bad, rec.Code)
		}
	}
	if got := decodePatterns(t, getJSON(t, s, "/api/proxy/passthrough")); len(got) != 0 {
		t.Fatalf("patterns = %v; refused posts must store nothing", got)
	}
}

func TestPassthroughEndpointWithoutAPolicyReportsUnavailableNotAFakeEmptyList(t *testing.T) {
	s := NewServer(core.NewTrafficStore(), core.NewScope())

	rec := getJSON(t, s, "/api/proxy/passthrough")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; a server with no TLS policy must admit it rather than serve an empty list that cannot be edited", rec.Code)
	}
}

// burpsy-react-ui-n1fi: the two coupling switches round-trip through PUT and are reported on GET.
func TestPassthroughCouplingSwitchesRoundTrip(t *testing.T) {
	s := newPassthroughTestServer(t)

	var view passthroughView
	if err := json.Unmarshal(getJSON(t, s, "/api/proxy/passthrough").Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.ApplyOutOfScope || view.AutoAddOnFailure {
		t.Errorf("defaults are not both off: %+v", view)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/proxy/passthrough",
		strings.NewReader(`{"apply_out_of_scope":true,"auto_add_on_failure":true}`))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.ApplyOutOfScope || !view.AutoAddOnFailure {
		t.Errorf("the switches did not take: %+v", view)
	}
	if !s.tlsPolicy.ApplyOutOfScope() || !s.tlsPolicy.AutoAddOnFailure() {
		t.Error("the PUT did not reach the live policy")
	}

	// A partial PUT changes only the field it names.
	s.mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/api/proxy/passthrough",
		strings.NewReader(`{"auto_add_on_failure":false}`)))
	if !s.tlsPolicy.ApplyOutOfScope() || s.tlsPolicy.AutoAddOnFailure() {
		t.Error("a partial PUT changed a field it did not name")
	}
}
