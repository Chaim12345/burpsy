package domexec

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingServer is an httptest server that counts the TCP connections it ACCEPTS — not requests,
// so a connection that was opened and then never carried a request still counts as egress.
func countingServer(t *testing.T, h http.Handler) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var accepts atomic.Int64
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			accepts.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &accepts
}

func gateFor(t *testing.T, raw string) testGate {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	return testGate{host: u.Hostname(), port: uint16(port)}
}

// burpsy-react-ui-browser-render-unscoped: a render of an in-scope page that pulls a script, an XHR, a
// fetch, an image and an iframe from an out-of-scope host makes ZERO connections to that host, while
// the page's in-scope subresource still loads (the positive control that the render ran at all).
func TestAGatedRenderNeverConnectsToAnOutOfScopeHost(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	if b.remoteURL != "" {
		t.Skip("the per-context proxy half needs a local Chrome")
	}
	outside, outsideAccepts := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, `document.body.setAttribute("data-outside","loaded");`)
	}))
	inside, _ := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/own.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = io.WriteString(w, `document.body.setAttribute("data-own","loaded");`)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<html><body>
			<script src="/own.js"></script>
			<script src="%[1]s/x.js"></script>
			<img src="%[1]s/pixel.gif">
			<iframe src="%[1]s/frame"></iframe>
			<script>
				fetch(%[1]q + "/api/fetch").catch(function(){});
				var x = new XMLHttpRequest(); x.open("GET", %[1]q + "/api/xhr"); x.send();
			</script></body></html>`, outside.URL)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	html, outcome, err := b.RenderedDOMGated(ctx, inside.URL+"/", RenderOptions{MaxWait: 3 * time.Second}, gateFor(t, inside.URL))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(html, `data-own="loaded"`) {
		t.Fatalf("the in-scope script did not run, so the render proves nothing: %s", html)
	}
	if strings.Contains(html, `data-outside`) {
		t.Errorf("the out-of-scope script ran: %s", html)
	}
	// Give any straggling connection (a late beacon, an iframe retry) time to land before counting.
	time.Sleep(500 * time.Millisecond)
	if n := outsideAccepts.Load(); n != 0 {
		t.Fatalf("the out-of-scope host accepted %d connection(s) during a gated render; want 0", n)
	}
	if len(outcome.Blocked) == 0 {
		t.Errorf("refusals were not reported on the outcome, so an incomplete render reads as complete")
	}
	outsideHost := strings.TrimPrefix(outside.URL, "http://")
	found := false
	for _, b := range outcome.Blocked {
		if strings.Contains(b, outsideHost) {
			found = true
		}
	}
	if !found {
		t.Errorf("Blocked does not name the out-of-scope host %s: %v", outsideHost, outcome.Blocked)
	}
}

// The render target itself is checked before any browser work.
func TestAGatedRenderRefusesAnOutOfScopeTargetAndANilGate(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	srv, accepts := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if _, _, err := b.RenderedDOMGated(context.Background(), srv.URL+"/", RenderOptions{}, testGate{host: "in.scope.invalid", port: 80}); err == nil {
		t.Fatal("an out-of-scope render target was rendered")
	}
	if _, _, err := b.RenderedDOMGated(context.Background(), srv.URL+"/", RenderOptions{}, nil); err == nil {
		t.Fatal("a render with no gate was accepted")
	}
	if n := accepts.Load(); n != 0 {
		t.Fatalf("a refused render still connected %d time(s)", n)
	}
}
