package scanner

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// frameableCases are X-Frame-Options / Content-Security-Policy header sets and whether a browser lets
// another origin frame the response. Each verdict was observed in Chrome (0vzb.32), and
// TestIsFrameableAgreesWithTheBrowser re-observes them whenever a browser is reachable.
var frameableCases = []struct {
	xfo, csp  []string
	frameable bool
}{
	{nil, nil, true},
	{[]string{"DENY"}, nil, false},
	{[]string{"SAMEORIGIN"}, nil, false},
	{[]string{"sameorigin"}, nil, false},
	{[]string{" deny "}, nil, false},
	{[]string{"ALLOWALL"}, nil, true},
	{[]string{"ALLOW-FROM http://127.0.0.1:1"}, nil, true},
	{[]string{"SAME-ORIGIN"}, nil, true},
	{[]string{"DENY;"}, nil, true},
	{[]string{","}, nil, true},
	{[]string{"SAMEORIGIN,"}, nil, false},
	{[]string{"SAMEORIGIN, SAMEORIGIN"}, nil, false},
	{[]string{"SAMEORIGIN, DENY"}, nil, false},
	{[]string{"SAMEORIGIN", "DENY"}, nil, false},
	{[]string{"ALLOWALL", "SAMEORIGIN"}, nil, false},
	{[]string{"ALLOWALL, foo"}, nil, false},
	{[]string{"foo, bar"}, nil, true},
	{nil, []string{"frame-ancestors 'self'"}, false},
	{nil, []string{"default-src 'self'; frame-ancestors 'none'"}, false},
	{[]string{"ALLOWALL"}, []string{"frame-ancestors 'self'"}, false},
	{[]string{"DENY"}, []string{"frame-ancestors *"}, true},
	{[]string{"DENY"}, []string{"frame-ancestors http: https:"}, true},
	{nil, []string{"default-src 'self'"}, true},
}

// Negative control: the old rule (one header value, compared whole) answers "frameable" for
// "SAMEORIGIN, DENY" and for two header lines, and "not frameable" for "frame-ancestors *".
func TestIsFrameableFollowsTheHTMLStandard(t *testing.T) {
	for _, c := range frameableCases {
		if got := IsFrameableHeaders(c.xfo, c.csp); got != c.frameable {
			t.Errorf("X-Frame-Options %q, CSP %q: frameable=%v, want %v", c.xfo, c.csp, got, c.frameable)
		}
	}
}

// Every verdict above, re-observed: a page on one origin frames a page on another that sends the
// headers, and the framed page reports in by postMessage only if the browser rendered it.
func TestIsFrameableAgreesWithTheBrowser(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping.js" {
			// An external same-origin script, so a policy without 'unsafe-inline' still lets the
			// framed page report in: the test reads framing, not script policy.
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write([]byte(`top.postMessage("framed","*")`))
			return
		}
		var c struct{ XFO, CSP []string }
		_ = json.Unmarshal([]byte(r.URL.Query().Get("h")), &c)
		for _, v := range c.XFO {
			w.Header().Add("X-Frame-Options", v)
		}
		for _, v := range c.CSP {
			w.Header().Add("Content-Security-Policy", v)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<script src="/ping.js"></script>`))
	}))
	defer target.Close()
	framer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<script>window.got=[];addEventListener("message",e=>got.push(e.data))</script>` +
			`<iframe src="` + html.EscapeString(r.URL.Query().Get("u")) + `"></iframe>`))
	}))
	defer framer.Close()
	// Two ports on one host are two origins.
	framerURL := strings.Replace(framer.URL, "127.0.0.1", "localhost", 1)

	var actx context.Context
	var cancel context.CancelFunc
	if remote := os.Getenv("BURPSY_DOM_REMOTE"); remote != "" {
		actx, cancel = chromedp.NewRemoteAllocator(context.Background(), remote)
	} else {
		actx, cancel = chromedp.NewExecAllocator(context.Background(),
			append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", true))...)
	}
	defer cancel()
	for i, c := range frameableCases {
		h, _ := json.Marshal(struct{ XFO, CSP []string }{c.xfo, c.csp})
		u := target.URL + "/?h=" + url.QueryEscape(string(h))
		ctx, cancelTab := chromedp.NewContext(actx)
		ctx, cancelTimeout := context.WithTimeout(ctx, 20*time.Second)
		var got []string
		err := chromedp.Run(ctx,
			chromedp.Navigate(framerURL+"/?u="+url.QueryEscape(u)),
			// A blocked frame never reports in, so absence is read after a fixed settle, not raced.
			chromedp.Sleep(1500*time.Millisecond),
			chromedp.Evaluate(`window.got`, &got),
		)
		if err != nil {
			cancelTimeout()
			cancelTab()
			if i == 0 {
				t.Skipf("no browser reachable, so the verdicts are NOT re-observed in this run: %v", err)
			}
			t.Fatalf("case %d: %v", i, err)
		}
		cancelTimeout()
		cancelTab()
		if framed := len(got) > 0; framed != c.frameable {
			t.Errorf("X-Frame-Options %q, CSP %q: the browser framed it=%v, the table says %v", c.xfo, c.csp, framed, c.frameable)
		}
		if IsFrameableHeaders(c.xfo, c.csp) != (len(got) > 0) {
			t.Errorf("X-Frame-Options %q, CSP %q: IsFrameableHeaders disagrees with the browser", c.xfo, c.csp)
		}
	}
}
