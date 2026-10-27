package vulnapp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A chunked body has ContentLength -1: the handler must read it, not panic sizing a buffer from it.
func TestSppjJSONReadsAChunkedBody(t *testing.T) {
	srv := httptest.NewServer(Handler())
	t.Cleanup(srv.Close)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/sppj/safe/json/profile", io.MultiReader(strings.NewReader(`{"name":`), strings.NewReader(`"a"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1 // sent chunked
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(got), `"saved":1`) {
		t.Fatalf("chunked body: HTTP %d %s", resp.StatusCode, got)
	}
}
