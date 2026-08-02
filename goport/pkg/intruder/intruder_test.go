package intruder

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"burpsy-go/pkg/store"
)

func TestIntruderPointsDiscovery(t *testing.T) {
	ts := store.NewTrafficStore()
	raw := []byte("GET /login?user=admin&pass=secret HTTP/1.1\r\nHost: target.test\r\n\r\n")
	msgID := ts.Put(raw, store.Request)

	intr := NewIntruder(ts)
	pointsVal, err := intr.Points(msgID, true)
	if err != nil {
		t.Fatalf("points discovery failed: %v", err)
	}

	points := pointsVal.([]PointView)
	if len(points) != 2 {
		t.Errorf("expected 2 discovered parameters, got %d", len(points))
	}

	if points[0].Label != "user" || points[0].Current != "admin" {
		t.Errorf("unexpected first parameter: %+v", points[0])
	}
	if points[1].Label != "pass" || points[1].Current != "secret" {
		t.Errorf("unexpected second parameter: %+v", points[1])
	}
}

func TestIntruderRunSniperAttack(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Attack backend received: " + r.URL.RawQuery))
	}))
	defer ts.Close()

	trafficStore := store.NewTrafficStore()
	rawReq := []byte("GET /login?user=admin&pass=secret HTTP/1.1\r\nHost: target.test\r\n\r\n")
	msgID := trafficStore.Put(rawReq, store.Request)

	intr := NewIntruder(trafficStore)

	reqMap := map[string]interface{}{
		"msg_id":       uint64(msgID),
		"target":       ts.URL,
		"mode":         "sniper",
		"points":       []int{0}, // inject only into parameter "user"
		"payload_sets": [][]string{{"payload1", "payload2"}},
		"rps":          100.0,
		"max_requests": 2,
	}

	resVal, err := intr.Run(reqMap)
	if err != nil {
		t.Fatalf("intruder run sniper failed: %v", err)
	}

	attempts := resVal.([]AttemptView)
	if len(attempts) != 2 {
		t.Errorf("expected 2 sniper attempts, got %d", len(attempts))
	}

	if attempts[0].Payload != "payload1" {
		t.Errorf("expected payload1, got %q", attempts[0].Payload)
	}
	if attempts[1].Payload != "payload2" {
		t.Errorf("expected payload2, got %q", attempts[1].Payload)
	}
}
