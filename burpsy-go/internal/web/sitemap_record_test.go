package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-4bfp: POST /api/sitemap/record through the real mux.

func storeExchange(t *testing.T, s *Server, host, path string) core.ExchangeID {
	t.Helper()
	id, err := s.store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	status := uint16(200)
	s.store.AddExchange(&core.Exchange{Request: core.MsgPtr(id), Host: host, Port: 80, Method: "GET", Path: path, Status: &status})
	all := s.store.Exchanges()
	return all[len(all)-1].ID
}

func doJSON(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestSitemapRecordByExchangeID(t *testing.T) {
	s := newTestServer()
	id := storeExchange(t, s, "shop.test", "/admin/panel")
	idJSON, _ := json.Marshal(map[string]any{"exchange_id": id})

	// The map follows the store: the exchange is already on it, and the reply says so.
	rec := doJSON(t, s, http.MethodPost, "/api/sitemap/record", string(idJSON))
	if rec.Code != http.StatusOK {
		t.Fatalf("record answered %d: %s", rec.Code, rec.Body.String())
	}
	var view map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view["already_on_map"] != true || view["recorded"] != false || view["was_suppressed"] != false ||
		view["node_key"] != nodeKey("shop.test", 80, false, "/admin/panel") || view["path"] != "/admin/panel" {
		t.Fatalf("unexpected reply for an exchange already on the map: %s", rec.Body.String())
	}

	// Delete the host from the map, then record the exchange: it comes back, pinned.
	if rec := doJSON(t, s, http.MethodDelete, "/api/sitemap", `{"host":"shop.test","port":80,"tls":false,"path":"","kind":"host"}`); rec.Code != http.StatusOK {
		t.Fatalf("suppress answered %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, s, http.MethodGet, "/api/sitemap", ""); strings.Contains(rec.Body.String(), "/admin/panel") {
		t.Fatalf("the suppressed host is still on the map: %s", rec.Body.String())
	}
	rec = doJSON(t, s, http.MethodPost, "/api/sitemap/record", string(idJSON))
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if rec.Code != http.StatusOK || view["recorded"] != true || view["was_suppressed"] != true || view["already_on_map"] != false {
		t.Fatalf("recording the suppressed exchange answered %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, s, http.MethodGet, "/api/sitemap", ""); !strings.Contains(rec.Body.String(), "/admin/panel") {
		t.Fatalf("the recorded exchange is not on the map: %s", rec.Body.String())
	}

	// Refusals: no such exchange, no id, wrong verb.
	if rec := doJSON(t, s, http.MethodPost, "/api/sitemap/record", `{"exchange_id":99999}`); rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown id answered %d", rec.Code)
	}
	if rec := doJSON(t, s, http.MethodPost, "/api/sitemap/record", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("a missing id answered %d", rec.Code)
	}
}
