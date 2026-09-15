package web

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---- /api/proxy/listener as a collection (burpsy-react-ui-pfeg) -------------------
//
// Burp's page leads with a LIST of listeners, each with its own redirect target, force-TLS
// and invisible-proxying settings. These tests pin the wire shape and, in particular, the
// two refusals the bead insists on: a listener that cannot bind is refused with the reason
// and is NOT added, and removal has a stated policy rather than an accident.
//
// The route is the one this package owns; the collection is addressed by ?id= rather than
// by /api/proxy/listeners/{id} because the mux registers this path as an exact match in
// server.go. See the comment at the top of api_proxylistener.go.

type listenerRowJSON struct {
	ID           string `json:"id"`
	Bind         string `json:"bind"`
	BoundAddr    string `json:"bound_addr"`
	RedirectHost string `json:"redirect_host"`
	RedirectPort int    `json:"redirect_port"`
	ForceTLS     bool   `json:"force_tls"`
	Invisible    *bool  `json:"invisible"`
	Removable    bool   `json:"removable"`
}

func getListeners(t *testing.T, ts *Server) ([]listenerRowJSON, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/proxy/listener", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/proxy/listener = %d: %s", rec.Code, rec.Body.String())
	}
	var view struct {
		Listeners []listenerRowJSON `json:"listeners"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return view.Listeners, rec.Body.String()
}

func postListener(t *testing.T, ts *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/proxy/listener", strings.NewReader(body)))
	return rec
}

func Test_the_listener_collection_reaches_the_browser_as_an_array(t *testing.T) {
	ts, ps := startAPIProxy(t)
	rows, raw := getListeners(t, ts)

	// A Go nil slice marshals as null, and the console reads .length off this field —
	// assert the marshalled JSON, not the struct.
	if strings.Contains(raw, `"listeners":null`) {
		t.Fatalf("listeners went out as null, which takes the view down: %s", raw)
	}
	if !strings.Contains(raw, `"listeners":[`) {
		t.Fatalf("listeners is not an array: %s", raw)
	}
	if len(rows) != 1 {
		t.Fatalf("GET listed %d listeners, want the boot listener alone: %s", len(rows), raw)
	}
	boot := rows[0]
	if boot.ID != "default" || boot.BoundAddr != ps.ListenerAddr() {
		t.Errorf("the boot row is %+v, want id=default bound to %s", boot, ps.ListenerAddr())
	}
	if boot.Removable {
		t.Error("the boot listener is reported removable, but removing it is refused")
	}
	// nil, not false: the boot listener inherits the process-wide invisible switch, and the
	// console has to be able to tell "inherit" from "off".
	if boot.Invisible != nil {
		t.Errorf("the boot listener's invisible is %v, want null (inherit)", *boot.Invisible)
	}
}

func Test_posting_a_listener_binds_it_and_the_new_socket_accepts(t *testing.T) {
	ts, _ := startAPIProxy(t)

	rec := postListener(t, ts, `{"bind":"127.0.0.1:0","redirect_host":"example.test","redirect_port":8443,"force_tls":true,"invisible":false}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/proxy/listener = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var added listenerRowJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &added); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if added.BoundAddr == "" || strings.HasSuffix(added.BoundAddr, ":0") {
		t.Fatalf("the added listener reported %q, want a resolved host:port", added.BoundAddr)
	}
	if added.RedirectHost != "example.test" || added.RedirectPort != 8443 || !added.ForceTLS {
		t.Errorf("the settings did not survive the round trip: %+v", added)
	}
	if added.Invisible == nil || *added.Invisible {
		t.Errorf("invisible:false round-tripped as %v, want an explicit false", added.Invisible)
	}
	if !added.Removable {
		t.Error("a listener added on this page is reported as not removable")
	}

	// The socket is real: something accepts on it.
	conn, err := net.DialTimeout("tcp", added.BoundAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("the added listener does not accept connections: %v", err)
	}
	conn.Close()

	rows, raw := getListeners(t, ts)
	if len(rows) != 2 || rows[1].ID != added.ID {
		t.Fatalf("GET lists %s, want the boot listener then %s", raw, added.ID)
	}
}

func Test_a_listener_that_cannot_bind_is_refused_with_the_reason_and_not_listed(t *testing.T) {
	ts, _ := startAPIProxy(t)

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy a port: %v", err)
	}
	defer taken.Close()

	rec := postListener(t, ts, `{"bind":"`+taken.Addr().String()+`"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST onto a taken port = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), taken.Addr().String()) {
		t.Errorf("the refusal does not name the address that failed: %s", rec.Body.String())
	}
	if rows, raw := getListeners(t, ts); len(rows) != 1 {
		t.Errorf("a listener that could not bind was listed anyway: %s", raw)
	}

	// A caller's own mistake stays 400, and the refusal says what is wrong.
	for _, tc := range []struct{ body, want string }{
		{`{"bind":"8080"}`, "host:port"},
		{`{"bind":"127.0.0.1:0","redirect_host":"http://example.test"}`, "scheme"},
		{`{"bind":"127.0.0.1:0","redirect_host":"example.test:8443"}`, "redirect-port"},
		{`{"bind":"127.0.0.1:0","redirect_port":70000}`, "65535"},
	} {
		rec := postListener(t, ts, tc.body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s = %d, want 400: %s", tc.body, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("POST %s refused with %q, want it to mention %q", tc.body, strings.TrimSpace(rec.Body.String()), tc.want)
		}
	}
	if rows, _ := getListeners(t, ts); len(rows) != 1 {
		t.Errorf("a refused listener was added: %d listeners, want 1", len(rows))
	}
}

func Test_putting_a_listener_id_replaces_its_settings_and_leaves_the_legacy_put_alone(t *testing.T) {
	ts, ps := startAPIProxy(t)
	rec := postListener(t, ts, `{"bind":"127.0.0.1:0"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	var added listenerRowJSON
	json.Unmarshal(rec.Body.Bytes(), &added)

	// A spec-only edit keeps the socket where it is — see UpdateListener.
	rec = httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/proxy/listener?id="+added.ID,
		strings.NewReader(`{"bind":"`+added.Bind+`","redirect_host":"127.0.0.1","redirect_port":9,"invisible":true}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT ?id= = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var updated listenerRowJSON
	json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated.BoundAddr != added.BoundAddr {
		t.Errorf("a settings-only edit moved the socket from %s to %s", added.BoundAddr, updated.BoundAddr)
	}
	if updated.RedirectHost != "127.0.0.1" || updated.RedirectPort != 9 || updated.Invisible == nil || !*updated.Invisible {
		t.Errorf("the edit did not take: %+v", updated)
	}

	// An id that names nothing is 404, not a silently created listener.
	rec = httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/proxy/listener?id=listener-nope",
		strings.NewReader(`{"bind":"127.0.0.1:0"}`)))
	if rec.Code != http.StatusNotFound {
		t.Errorf("PUT an unknown id = %d, want 404: %s", rec.Code, rec.Body.String())
	}

	// The legacy bodied PUT still re-binds the boot listener and still answers the old shape.
	before := ps.ListenerAddr()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	freeAddr := free.Addr().String()
	free.Close()
	rec = httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/proxy/listener",
		strings.NewReader(`{"bind":"`+freeAddr+`"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy PUT = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var view struct {
		Bind         string `json:"bind"`
		PreviousBind string `json:"previous_bind"`
	}
	json.Unmarshal(rec.Body.Bytes(), &view)
	if view.Bind != freeAddr || view.PreviousBind != before {
		t.Errorf("legacy PUT answered %+v, want bind=%s previous=%s", view, freeAddr, before)
	}
}

func Test_removing_a_listener_has_a_stated_policy(t *testing.T) {
	ts, _ := startAPIProxy(t)

	// The boot listener is refused, and the refusal says what to do instead.
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/proxy/listener?id=default", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("DELETE the boot listener = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "re-bind") {
		t.Errorf("the refusal does not say what to do instead: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/proxy/listener?id=listener-nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("DELETE an unknown id = %d, want 404", rec.Code)
	}

	rec = httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/proxy/listener", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("DELETE with no id = %d, want 400", rec.Code)
	}

	// An added listener goes, and the collection says so.
	created := postListener(t, ts, `{"bind":"127.0.0.1:0"}`)
	var added listenerRowJSON
	json.Unmarshal(created.Body.Bytes(), &added)
	rec = httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/proxy/listener?id="+added.ID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE an added listener = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	rows, raw := getListeners(t, ts)
	if len(rows) != 1 || rows[0].ID != "default" {
		t.Errorf("after removal the collection is %s, want the boot listener alone", raw)
	}
}
