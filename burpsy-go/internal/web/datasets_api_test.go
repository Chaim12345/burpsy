package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-co88: GET /api/datasets/{source}.

func addExchange(t *testing.T, s *Server, host, path string, status uint16, src core.Source, task uint64) {
	t.Helper()
	id, err := s.store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	s.store.AddExchange(&core.Exchange{Request: core.MsgPtr(id), Host: host, Port: 80, Method: "GET", Path: path, Status: &status, Source: src, TaskID: task})
}

type datasetReply struct {
	Source     string           `json:"source"`
	Columns    []string         `json:"columns"`
	TotalRows  int              `json:"total_rows"`
	Matched    int              `json:"matched"`
	Returned   int              `json:"returned"`
	NextOffset *int             `json:"next_offset"`
	Rows       []map[string]any `json:"rows"`
	Facets     []struct {
		Column   string `json:"column"`
		Distinct int    `json:"distinct"`
		Values   []struct {
			Value string `json:"value"`
			Count int    `json:"count"`
		} `json:"values"`
	} `json:"facets"`
	Status string `json:"status"`
}

func getDataset(t *testing.T, s *Server, path string) (datasetReply, string, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var out datasetReply
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decoding %s: %v", path, err)
		}
	}
	return out, rec.Body.String(), rec.Code
}

func TestAHistoryIsPagedToItsLastRow(t *testing.T) {
	s := newTestServer()
	for i := 0; i < 120; i++ {
		addExchange(t, s, "shop.test", fmt.Sprintf("/p/%d", i), uint16(200+(i%3)*100), core.SourceProxy, 0)
	}
	// Tool-sent rows are not history, exactly as /api/history decides.
	addExchange(t, s, "shop.test", "/repeated", 200, core.SourceRepeater, 0)

	var ids []float64
	offset, pages := 0, 0
	for {
		got, raw, code := getDataset(t, s, fmt.Sprintf("/api/datasets/history?limit=25&offset=%d", offset))
		if code != http.StatusOK || got.TotalRows != 120 || got.Matched != 120 {
			t.Fatalf("page at %d answered %d: %.300s", offset, code, raw)
		}
		for _, r := range got.Rows {
			ids = append(ids, r["id"].(float64))
		}
		pages++
		if got.NextOffset == nil {
			if !strings.Contains(raw, `"next_offset":null`) || !strings.Contains(raw, `"facets":null`) {
				t.Fatalf("the last page does not say so, or facets are not null unasked: %.300s", raw)
			}
			break
		}
		offset = *got.NextOffset
	}
	if pages != 5 || len(ids) != 120 {
		t.Fatalf("%d pages, %d rows", pages, len(ids))
	}
	for i, id := range ids {
		if int(id) != i {
			t.Fatalf("row %d has id %v; pages overlapped or skipped", i, id)
		}
	}

	// A dataset row is the /api/history row, column for column.
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/history?limit=1", nil))
	var hist []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &hist)
	newest, _, _ := getDataset(t, s, "/api/datasets/history?sort_order=desc&limit=1")
	for k, v := range hist[0] {
		if _, nested := v.(map[string]any); nested {
			continue
		}
		if fmt.Sprint(newest.Rows[0][k]) != fmt.Sprint(v) {
			t.Fatalf("column %q: dataset %v, /api/history %v", k, newest.Rows[0][k], v)
		}
	}
}

func TestADatasetFiltersSortsProjectsAndFacets(t *testing.T) {
	s := newTestServer()
	for i := 0; i < 30; i++ {
		host := "a.test"
		if i%2 == 1 {
			host = "b.test"
		}
		addExchange(t, s, host, fmt.Sprintf("/item/%d", i), uint16(200+(i%3)*100), core.SourceProxy, 0)
	}
	got, raw, _ := getDataset(t, s, "/api/datasets/history?pattern=%5Eb%5C.test%24&columns=host&sort_by=id&sort_order=desc&return_columns=id,path&limit=5&facets=status")
	if got.Matched != 15 || got.Returned != 5 || got.Rows[0]["id"].(float64) != 29 || len(got.Rows[0]) != 2 {
		t.Fatalf("filter/sort/project wrong: %.400s", raw)
	}
	if len(got.Facets) != 1 || got.Facets[0].Column != "status" || got.Facets[0].Distinct != 3 {
		t.Fatalf("facets wrong: %+v", got.Facets)
	}
	total := 0
	for _, v := range got.Facets[0].Values {
		total += v.Count
	}
	if total != 15 {
		t.Fatalf("facet counts cover %d rows, not the 15 matched", total)
	}
	// An empty source answers rows [] — not null.
	empty := newTestServer()
	_, raw, _ = getDataset(t, empty, "/api/datasets/issues")
	if !strings.Contains(raw, `"rows":[]`) || !strings.Contains(raw, `"columns":[]`) {
		t.Fatalf("an empty dataset: %s", raw)
	}
}

func TestADatasetLongPollWakesOnANewRow(t *testing.T) {
	old := datasetPollInterval
	datasetPollInterval = 30 * time.Millisecond
	t.Cleanup(func() { datasetPollInterval = old })
	s := newTestServer()
	addExchange(t, s, "a.test", "/0", 200, core.SourceProxy, 0)
	go func() {
		time.Sleep(300 * time.Millisecond)
		addExchange(t, s, "a.test", "/1", 200, core.SourceProxy, 0)
	}()
	start := time.Now()
	got, raw, _ := getDataset(t, s, "/api/datasets/history?since=0&wait_seconds=20")
	if got.Status != "complete" || got.Matched != 1 || time.Since(start) > 5*time.Second {
		t.Fatalf("the long-poll did not wake on the new row (%v): %s", time.Since(start), raw)
	}
	got, raw, _ = getDataset(t, s, "/api/datasets/history?since=5&wait_seconds=1")
	if got.Status != "timeout" || !strings.Contains(raw, `"rows":[]`) {
		t.Fatalf("a wait with nothing new: %s", raw)
	}
}

func TestAnIntruderDatasetIsOneAttacksRequests(t *testing.T) {
	s := newTestServer()
	addExchange(t, s, "a.test", "/x", 200, core.SourceIntruder, 7)
	addExchange(t, s, "a.test", "/y", 500, core.SourceIntruder, 7)
	addExchange(t, s, "a.test", "/z", 200, core.SourceIntruder, 8)
	addExchange(t, s, "a.test", "/w", 200, core.SourceProxy, 7)
	got, raw, _ := getDataset(t, s, "/api/datasets/intruder/7")
	if got.Matched != 2 || got.Source != "intruder/7" {
		t.Fatalf("intruder/7: %s", raw)
	}
	for _, c := range []struct {
		path string
		code int
	}{
		{"/api/datasets/nope", 404}, {"/api/datasets/intruder", 400}, {"/api/datasets/history/3", 404},
		{"/api/datasets/history?limit=501", 400}, {"/api/datasets/history?pattern=(", 400},
		{"/api/datasets/history?wait_seconds=61", 400}, {"/api/datasets/intruder/x", 400},
	} {
		if _, raw, code := getDataset(t, s, c.path); code != c.code {
			t.Fatalf("%s answered %d (want %d): %s", c.path, code, c.code, raw)
		}
	}
	_, raw, code := getDataset(t, s, "/api/datasets/")
	if code != http.StatusOK || !strings.Contains(raw, `"intruder/{task_id}"`) || !strings.Contains(raw, `"name":"sitemap"`) {
		t.Fatalf("the listing: %d %s", code, raw)
	}
}
