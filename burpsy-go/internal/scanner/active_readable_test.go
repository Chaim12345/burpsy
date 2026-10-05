package scanner

import (
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// gzipEverything answers every request gzip-encoded, the way a CDN does for a browser that sent
// Accept-Encoding: gzip — which the probe harness replays verbatim from the captured request.
func gzipEverything(body func(r *http.Request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		fmt.Fprint(zw, body(r))
		_ = zw.Close()
	}
}

// burpsy-react-ui-s68u: the harness's baseline and its probes come back readable from a gzip origin,
// so a reflection check sees its payload reflected — before, both sides were compressed bytes and no
// payload was ever found in either.
func TestTheProbeHarnessReadsAGzipOriginsBaselineAndProbes(t *testing.T) {
	cc := harnessAgainst(t, gzipEverything(func(r *http.Request) string {
		return "<p>you sent q=" + r.URL.Query().Get("q") + "</p>"
	}), "/search?q=hello")

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	if !strings.Contains(h.Baseline().Body, "q=hello") {
		t.Fatalf("baseline body is not readable: %q", h.Baseline().Body)
	}
	var point = h.Points()[0]
	res, err := h.Send(context.Background(), point, "zq7canary")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(res.Body, "q=zq7canary") {
		t.Errorf("the probe's reflection is not visible: %q", res.Body)
	}
	if strings.Contains(string(res.Raw), "Content-Encoding") {
		t.Errorf("the probe's readable head still claims an encoding: %q", res.Raw)
	}
}

// The base response a typed probe is compared with reads decoded too: a stored gzip response's body
// matches the plaintext a net/http probe returns.
func TestTheActiveBaseResponseIsReadable(t *testing.T) {
	store := core.NewTrafficStore()
	html := "<p>base page</p>"
	respID, _ := store.Put(append([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"), gzipped(t, html)...), core.DirectionResponse)
	ex := &core.Exchange{Response: &respID, Host: "h", Port: 80, Method: "GET", Path: "/"}
	store.AddExchange(ex)
	s := NewActiveScanner(store, zap.NewNop())
	if got := s.getResponseBody(ex); got != html {
		t.Errorf("active base body = %q, want the decoded page", got)
	}
	if got := responseRaw(s, ex); !strings.HasSuffix(got, html) {
		t.Errorf("active base raw = %q", got)
	}
}
