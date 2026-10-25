package domexec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestARestrictedProbeRecordsTheRefusedSameHostRedirect(t *testing.T) {
	b := newTestBrowser(t)
	var escaped atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/outside" {
			escaped.Add(1)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<script>location.href='/outside';</script>`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	sess, err := b.NewSession(testGate{host: u.Hostname(), port: uint16(port), denyPrefix: "/outside"})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	sess.IgnoreCertificateErrors(true)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, probeErr := sess.Probe(ctx, srv.URL+"/allowed", "", `JSON.stringify({url:location.href,text:document.body.innerText.slice(0,400)})`)
	err = probeErr
	t.Logf("probe: %s %v", result, err)
	if err != nil && !strings.Contains(err.Error(), "ERR_BLOCKED_BY_CLIENT") {
		t.Fatal(err)
	}
	if escaped.Load() != 0 {
		t.Fatal("out-of-scope same-host redirect reached server")
	}
	if got := strings.Join(sess.RenderBlocked(), "\n"); !strings.Contains(got, "/outside") {
		t.Fatalf("refusal not recorded: %s", got)
	}
}

func TestARestrictedProbeBlocksWorkersFramesAndPopupsBeforeTheirRequests(t *testing.T) {
	b := newTestBrowser(t)
	var forbidden atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			return
		}
		if r.URL.Path != "/allowed" {
			forbidden.Add(1)
			t.Logf("unexpected request %s", r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<body>control<script>
try { new Worker('/worker.js'); } catch(e) {}
fetch('/api').catch(function(){}); try { new WebSocket(location.origin.replace('http','ws')+'/socket'); }catch(e){}
try { window.open('/popup'); } catch(e) {}
var f=document.createElement('iframe');f.src='/frame';document.body.appendChild(f);
</script>`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	sess, err := b.NewSession(testGate{host: u.Hostname(), port: uint16(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := sess.Probe(ctx, srv.URL+"/allowed", "", `document.body.innerText`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "control") {
		t.Fatalf("positive control page did not run: %s", out)
	}
	if forbidden.Load() != 0 {
		t.Fatalf("restricted surfaces made %d requests", forbidden.Load())
	}
}
