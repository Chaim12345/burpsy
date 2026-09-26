package scanner

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// TestAuditSendsRealRequests starts a local server that reflects the query
// parameter (an XSS sink) and verifies the active scanner actually dispatches
// crafted payloads over the network and reports the reflection.
func TestAuditSendsRealRequests(t *testing.T) {
	// Reflecting server: echoes ?xss= back into the body.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>" + r.URL.Query().Get("xss") + "</body></html>"))
		}))
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	portU64, _ := strconv.ParseUint(portStr, 10, 16)

	// Seed the store with an exchange for this target.
	store := core.NewTrafficStore()
	reqRaw := []byte("GET /search?xss=seed HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	reqID, _ := store.Put(reqRaw, core.DirectionRequest)
	respRaw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>seed</body></html>")
	respID, _ := store.Put(respRaw, core.DirectionResponse)
	store.AddExchange(&core.Exchange{
		Request:  core.MsgPtr(reqID),
		Response: &respID,
		Host:     "127.0.0.1",
		Port:     uint16(portU64),
		TLS:      false,
		Method:   "GET",
		Path:     "/search",
	})

	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig()))
	// Only XSS: keeps the test fast and deterministic.
	scan.WithConfig(&ScanConfig{
		MaxConcurrency:     4,
		Timeout:            5 * time.Second,
		CheckSqli:          false,
		CheckXss:           true,
		CheckPathTraversal: false,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	findings, err := scan.Audit(ctx, 0)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("no findings: the scanner did not detect the reflected XSS sink")
	}
	found := false
	for _, f := range findings {
		if f.Name == "Cross-site scripting (reflected)" {
			found = true
			if f.Evidence == "" {
				t.Error("finding has no evidence payload")
			}
		}
	}
	if !found {
		t.Errorf("no XSS finding in %+v", findings)
	}
}

// TestAuditFallsBackToStoredResponse verifies the offline path (no sender)
// still inspects the stored response for matchable content.
func TestAuditFallsBackToStoredResponse(t *testing.T) {
	store := core.NewTrafficStore()
	reqID, _ := store.Put([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n"), core.DirectionRequest)
	respRaw := []byte("HTTP/1.1 200 OK\r\n\r\n<html>hello root:x:0:0: world</html>")
	respID, _ := store.Put(respRaw, core.DirectionResponse)
	store.AddExchange(&core.Exchange{
		Request:  core.MsgPtr(reqID),
		Response: &respID,
		Host:     "h",
		Port:     80,
		Method:   "GET",
		Path:     "/",
	})

	scan := NewActiveScanner(store, zap.NewNop()) // no sender
	scan.WithConfig(&ScanConfig{
		MaxConcurrency:     2,
		Timeout:            3 * time.Second,
		CheckSqli:          false,
		CheckXss:           false,
		CheckPathTraversal: true,
	})

	findings, err := scan.Audit(context.Background(), 0)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("no findings: stored response path traversal not detected")
	}
	// The catalog row is "File path traversal". The predecessor emitted "Path Traversal", a name
	// no catalog row carries, so its findings could not be attributed to a TypeIndex at all.
	if findings[0].Name != "File path traversal" {
		t.Errorf("finding = %q, want the catalog row name %q", findings[0].Name, "File path traversal")
	}
}

// A runtime config edit lands atomically from a concurrent dispatcher's point of view: the count
// is read through the same snapshot discipline the audit uses, so this fails under -race if any
// reader reaches straight into s.config while PUT /api/scanner/config writes.
func TestRuntimeConfigEditIsAtomicAgainstTheDispatchCount(t *testing.T) {
	s := NewActiveScanner(core.NewTrafficStore(), zap.NewNop())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			s.UpdateScanConfig(func(c *ScanConfig) { c.CheckXXE = i%2 == 0 })
			_ = s.ActiveCheckCount()
		}
	}()
	for i := 0; i < 2000; i++ {
		_ = s.ConfigSnapshot()
		_ = s.ActiveCheckCount()
	}
	<-done
}
