package web

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Server cost of one xui update at scale. Run: go test ./internal/web -run xxx -bench XUI -benchtime 20x
func BenchmarkXUIMapWindow(b *testing.B) {
	for _, n := range []int{4000, 30000, 100000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := newTestServer()
			for i := 0; i < n; i++ {
				s.store.AddExchange(&core.Exchange{Host: "h.test", Port: 80, Method: "GET", Path: fmt.Sprintf("/item/%d", i)})
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.xuiHistoryWindow("")
			}
		})
	}
}

func BenchmarkXUIProveWindow(b *testing.B) {
	for _, n := range []int{10000, 30000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := newTestServer()
			for i := 0; i < n; i++ {
				s.findings.Add(core.NewFinding{Name: fmt.Sprintf("finding %d", i), Severity: core.Severity(i % 5), TaskID: 1,
					Target: core.FindingTarget{Host: "t.test", Port: 80, Path: fmt.Sprintf("/p%d", i)}})
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = streamBodyOnce(b, s)
			}
		})
	}
}

// streamBodyOnce drives the Prove stream just long enough for its first render.
func streamBodyOnce(b *testing.B, s *Server) int {
	b.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/x/prove/stream", nil).WithContext(ctx)
	rec := &stopRecorder{ResponseRecorder: httptest.NewRecorder(), cancel: cancel}
	s.mux.ServeHTTP(rec, req)
	return rec.Body.Len()
}

// stopRecorder cancels the request once the rows patch has been written.
type stopRecorder struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (r *stopRecorder) Write(p []byte) (int, error) {
	n, err := r.ResponseRecorder.Write(p)
	if bytes.Contains(p, []byte(`id="xui-rows"`)) {
		r.cancel()
	}
	return n, err
}
