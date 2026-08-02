package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"burpsy-go/pkg/scope"
	"burpsy-go/pkg/store"
)

func TestWebServerEndpoints(t *testing.T) {
	ts := store.NewTrafficStore()
	sc := scope.NewAllowEverythingScope()
	caPem := "---BEGIN CERTIFICATE---\nCA PEM DATA\n---END CERTIFICATE---"

	server := NewServer("127.0.0.1:0", ts, sc, caPem)

	// 1. Test GET /api/stats
	req := httptest.NewRequest("GET", "/api/stats", nil)
	rr := httptest.NewRecorder()
	server.Mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var stats map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &stats)
	if err != nil {
		t.Fatalf("failed to decode stats json: %v", err)
	}

	if stats["exchanges"].(float64) != 0 || stats["messages"].(float64) != 0 {
		t.Errorf("expected 0 exchanges and messages, got %v", stats)
	}

	// 2. Test GET /ca.crt
	req = httptest.NewRequest("GET", "/ca.crt", nil)
	rr = httptest.NewRecorder()
	server.Mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "BEGIN CERTIFICATE") {
		t.Errorf("expected CA PEM certificate body, got: %s", rr.Body.String())
	}
}

func TestWebDecoderAndComparer(t *testing.T) {
	ts := store.NewTrafficStore()
	sc := scope.NewAllowEverythingScope()
	server := NewServer("127.0.0.1:0", ts, sc, "")

	// 1. Test POST /api/tools/decode (Rot13 & Base64)
	body, _ := json.Marshal(map[string]string{
		"text": "decodeme",
		"type": "rot13",
	})
	req := httptest.NewRequest("POST", "/api/tools/decode", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	server.Mux.ServeHTTP(rr, req)

	var res map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if res["result"] != "qrpbqrzr" { // rot13 of "decodeme" is "qrpbqrzr"
		t.Errorf("expected qrpbqrzr, got %q", res["result"])
	}

	// 2. Test POST /api/tools/compare (equal)
	body, _ = json.Marshal(map[string]string{
		"left":  "line1\nline2",
		"right": "line1\nline2",
	})
	req = httptest.NewRequest("POST", "/api/tools/compare", bytes.NewBuffer(body))
	rr = httptest.NewRecorder()
	server.Mux.ServeHTTP(rr, req)

	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if res["equal"].(bool) != true {
		t.Errorf("expected equal to be true")
	}

	// 3. Test POST /api/tools/compare (different)
	body, _ = json.Marshal(map[string]string{
		"left":  "line1\nline2",
		"right": "line1\nlineX",
	})
	req = httptest.NewRequest("POST", "/api/tools/compare", bytes.NewBuffer(body))
	rr = httptest.NewRecorder()
	server.Mux.ServeHTTP(rr, req)

	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if res["equal"].(bool) != false {
		t.Errorf("expected equal to be false")
	}
}

func TestWebSequencer(t *testing.T) {
	ts := store.NewTrafficStore()
	sc := scope.NewAllowEverythingScope()
	server := NewServer("127.0.0.1:0", ts, sc, "")

	body, _ := json.Marshal(map[string]interface{}{
		"tokens": []string{"a", "a", "b", "b"},
	})
	req := httptest.NewRequest("POST", "/api/sequencer/analyse", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	server.Mux.ServeHTTP(rr, req)

	var res map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if res["total"].(float64) != 4 {
		t.Errorf("expected total to be 4, got %v", res["total"])
	}
	if res["entropy"].(float64) != 1.0 { // Shannon entropy of evenly split 2 keys is 1.0
		t.Errorf("expected entropy to be 1.0, got %v", res["entropy"])
	}
}
