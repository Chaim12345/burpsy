package web

// Anomaly ranking reaches the wire (burpsy-react-ui-pglp): /api/intruder/run's report names the
// attributes that varied and ranks every attempt, and the odd response out ranks first.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func TestIntruderRunReportsAnomalyRanksAndVariantAttributes(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "admin" {
			http.Redirect(w, r, "/admin/home", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><title>Search</title>nothing found</html>"))
	}))
	defer origin.Close()
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	qIndex := pointIndex(t, srv, id, "url_param_value", "q")

	var out map[string]json.RawMessage
	if code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       origin.URL,
		"mode":         "sniper",
		"points":       []int{qIndex},
		"payload_sets": [][]string{{"one", "two", "admin", "four", "five"}},
		"max_requests": 100,
		"rps":          1000,
	}, &out); code != http.StatusOK {
		t.Fatalf("run status = %d, want 200", code)
	}
	var rep map[string]json.RawMessage
	if err := json.Unmarshal(out["report"], &rep); err != nil {
		t.Fatalf("report = %s: %v", out["report"], err)
	}
	var variant []string
	if err := json.Unmarshal(rep["variant_attributes"], &variant); err != nil || variant == nil {
		t.Fatalf("variant_attributes = %s, want a JSON array", rep["variant_attributes"])
	}
	if !strings.Contains(string(rep["variant_attributes"]), `"status_code"`) ||
		!strings.Contains(string(rep["variant_attributes"]), `"location"`) {
		t.Errorf("variant_attributes = %s, want status_code and location among them", rep["variant_attributes"])
	}
	var attempts []struct {
		Ordinal     int  `json:"ordinal"`
		Status      *int `json:"status"`
		AnomalyRank *int `json:"anomaly_rank"`
	}
	if err := json.Unmarshal(rep["attempts"], &attempts); err != nil || len(attempts) != 5 {
		t.Fatalf("attempts = %s (%v), want five rows", rep["attempts"], err)
	}
	for _, a := range attempts {
		if a.AnomalyRank == nil {
			t.Fatalf("attempt %d has no anomaly_rank on the wire", a.Ordinal)
		}
		redirected := a.Status != nil && *a.Status == http.StatusFound
		if redirected != (*a.AnomalyRank == 1) {
			t.Errorf("attempt %d (status %v) has anomaly rank %d; only the redirect should rank 1", a.Ordinal, *a.Status, *a.AnomalyRank)
		}
	}
}
