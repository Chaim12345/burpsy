package intruder

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func testLogger() *zap.Logger {
	return zap.NewNop()
}

func TestPayloadGeneratorGenerateNumbers(t *testing.T) {
	pg := NewPayloadGenerator()
	got := pg.GenerateNumbers(1, 5)
	want := []string{"1", "2", "3", "4", "5"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("payload[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestPayloadGeneratorGenerateFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payloads.txt")
	content := "admin\nroot\n\n  spaced  \n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	pg := NewPayloadGenerator()
	got, err := pg.GenerateFromFile(path)
	if err != nil {
		t.Fatalf("GenerateFromFile: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (blank line skipped)", len(got))
	}
	if got[2] != "spaced" {
		t.Errorf("payload[2] = %q, want %q (trimmed)", got[2], "spaced")
	}

	// Missing file must surface the error.
	if _, err := pg.GenerateFromFile(filepath.Join(dir, "nope.txt")); err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// TestRunSendsOverPlainHTTP starts a local HTTP server and drives a real
// intruder attack against it, verifying status parsing and result delivery.
func TestRunSendsOverPlainHTTP(t *testing.T) {
	var mu sync.Mutex
	received := make([]string, 0)
	srv := &http.Server{Addr: "127.0.0.1:0"}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			received = append(received, r.URL.Query().Get("q"))
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		}))
	}()
	_ = srv

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	portU64, _ := strconv.ParseUint(portStr, 10, 16)
	port := uint16(portU64)

	intr := NewIntruder(testLogger()).
		WithConfig(&AttackConfig{MaxConcurrency: 4, Timeout: 5 * time.Second})

	base := "GET /search?q=§test§ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
	payloads := []string{"one", "two", "three"}
	results, err := intr.Run(context.Background(), base, "127.0.0.1", port, false, payloads, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	count := 0
	for res := range results {
		count++
		if res.Error != nil {
			t.Errorf("result error: %v", res.Error)
		}
		if res.StatusCode != 200 {
			t.Errorf("status = %d, want 200", res.StatusCode)
		}
		if res.Payload == "" {
			t.Error("result payload empty")
		}
	}
	if count != len(payloads) {
		t.Errorf("results = %d, want %d", count, len(payloads))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != len(payloads) {
		t.Errorf("server received %d requests, want %d", len(received), len(payloads))
	}
	for _, p := range payloads {
		found := false
		for _, r := range received {
			if r == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("server never saw payload %q in %v", p, received)
		}
	}
}

func TestInjectPayloadMarkers(t *testing.T) {
	intr := NewIntruder(testLogger())
	base := "GET /search?q=§x§ HTTP/1.1\r\nHost: h\r\n\r\n"
	got := intr.injectPayload(base, nil, "boom")
	if !strings.Contains(got, "q=boom") {
		t.Errorf("marker not replaced: %q", got)
	}
	if strings.Contains(got, "§") {
		t.Errorf("markers left in request: %q", got)
	}
}
