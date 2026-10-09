package h2test

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// TEMPORARY live origin for manual verification; never committed.
func TestZZLiveOrigin(t *testing.T) {
	if os.Getenv("H2TEST_LIVE") == "" {
		t.Skip("live origin only")
	}
	s := Start(t, Options{ResponseBody: []byte("live origin answered\n")})
	base := httptest.NewTLSServer(http.NotFoundHandler())
	os.WriteFile("/tmp/i9ti2-live/origin-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: base.Certificate().Raw}), 0o644)
	base.Close()
	os.WriteFile("/tmp/i9ti2-live/origin.port", []byte(fmt.Sprint(s.Port)), 0o644)
	for i := 0; i < 360; i++ {
		time.Sleep(5 * time.Second)
		for _, r := range s.Requests() {
			_ = r
		}
		var lines string
		for _, r := range s.Requests() {
			lines += fmt.Sprintf("%q body=%q\n", r.Fields, r.Body)
		}
		os.WriteFile("/tmp/i9ti2-live/origin.requests", []byte(lines), 0o644)
	}
}
