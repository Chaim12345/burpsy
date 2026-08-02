package repeater

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"burpsy-go/pkg/store"
)

func TestRepeaterSend(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello from repeater backend!"))
	}))
	defer ts.Close()

	trafficStore := store.NewTrafficStore()
	rep := NewRepeater(trafficStore)

	rawReq := []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
	resVal, err := rep.Send(ts.URL, rawReq, 1000, store.Http1)
	if err != nil {
		t.Fatalf("repeater Send failed: %v", err)
	}

	res := resVal.(SendResp)
	if res.Status != 200 {
		t.Errorf("expected status 200, got %d", res.Status)
	}

	exchanges := trafficStore.Exchanges(0, 10)
	if len(exchanges) != 1 {
		t.Fatalf("expected 1 exchange in store, got %d", len(exchanges))
	}

	if exchanges[0].ID != res.ExchangeID {
		t.Errorf("exchange IDs do not match")
	}
}
