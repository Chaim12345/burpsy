package web

// Burp's "Scan using HTTP & HTTPS" vs "Scan using my specified protocols" (burpsy-react-ui-in8j).

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestSeedProtocolExpansion(t *testing.T) {
	got, err := expandSeedProtocols([]string{"shop.test/app", "https://a.test:8443/x", "http://shop.test/app"}, "both")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://shop.test/app", "https://shop.test/app", "http://a.test:8443/x", "https://a.test:8443/x"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("both = %v, want %v (twins added, port kept, duplicates dropped)", got, want)
	}
	if got, err := expandSeedProtocols([]string{"https://a.test/"}, ""); err != nil || !reflect.DeepEqual(got, []string{"https://a.test/"}) {
		t.Errorf("specified keeps seeds as written: %v %v", got, err)
	}
	if _, err := expandSeedProtocols([]string{"a.test"}, "specified"); err == nil || !strings.Contains(err.Error(), "HTTP & HTTPS") {
		t.Errorf("a schemeless seed under specified must be refused naming the option: %v", err)
	}
	if _, err := expandSeedProtocols([]string{"https://a.test"}, "gopher"); err == nil {
		t.Error("an unknown mode must be refused")
	}
}

func TestACrawlUnderBothProtocolsSeedsEachScheme(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	rec := postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{"127.0.0.1:1/"}, "protocols": "both"})
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("crawl = %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Seeds []string `json:"seeds"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if !reflect.DeepEqual(out.Seeds, []string{"http://127.0.0.1:1/", "https://127.0.0.1:1/"}) {
		t.Errorf("seeds = %v, want both schemes; body %s", out.Seeds, rec.Body.String())
	}
	if rec := postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{"127.0.0.1:1/"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("schemeless seed without both = %d, want 400", rec.Code)
	}
}
