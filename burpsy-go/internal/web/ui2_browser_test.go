package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
	"github.com/chromedp/chromedp"
)

// TestUI2IntruderLaunchBrowserFinalClick is the final-click half the handler tests cannot give:
// a real browser, real htmx, the real confirm fragment. The operator's actual clicks carry the
// launch from the points listing through the minted confirmation to the gated dispatch and the
// finished attack's results — the chain whose breaks (dropped all_points, blank re-rendered
// form, unreachable results) only ever showed up in a browser.
func TestUI2IntruderLaunchBrowserFinalClick(t *testing.T) {
	if !chromeAvailable() {
		domexectest.Skip(t, "no Chrome on PATH")
	}
	s := newTestServer()
	// A loopback victim the attack can actually reach: p.test's DNS failure can hang for
	// minutes under a sandboxed resolver, and a timeout is not the chain under test.
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("victim-ok"))
	}))
	t.Cleanup(victim.Close)
	vhost := strings.TrimPrefix(victim.URL, "http://")
	s.scope.AddInclude("127.0.0.1")
	seedUI2Exchange(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: "+vhost+"\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nvictim-ok")
	srv := httptest.NewServer(s.mux)
	t.Cleanup(srv.Close)

	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("no-sandbox", true))
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, 90*time.Second)
	defer cancelTimeout()

	var results string
	stages := []struct {
		name string
		act  chromedp.Action
	}{
		{"navigate", chromedp.Navigate(srv.URL + "/ui2/intruder")},
		{"wait points button", chromedp.WaitVisible(`form[hx-post="/ui2/intruder/points"] button`, chromedp.ByQuery)},
		{"click list points", chromedp.Click(`form[hx-post="/ui2/intruder/points"] button`, chromedp.ByQuery)},
		{"wait points out", chromedp.WaitVisible(`#points-out .badge`, chromedp.ByQuery)},
		{"fill payloads", chromedp.SetValue(`form[hx-post="/ui2/intruder/confirm"] textarea[name="payloads"]`, "admin\nroot", chromedp.ByQuery)},
		{"click prepare", chromedp.Click(`form[hx-post="/ui2/intruder/confirm"] button[type="submit"]`, chromedp.ByQuery)},
		{"wait confirm", chromedp.WaitVisible(`#confirm-out form[hx-post="/ui2/intruder/run"] button[type="submit"]`, chromedp.ByQuery)},
		// The launch button renders disabled (data-arm-on-load); app.js arms it from the
		// button's own htmx:load, which fires only after htmx has bound the hx-post form.
		// Waiting for the enabled state is waiting for the same readiness an operator sees:
		// a click before arming is a no-op on a disabled control, never the native submit
		// that silently dropped the launch and leaked the minted call into the URL.
		{"wait armed", chromedp.WaitEnabled(`#confirm-out form[hx-post="/ui2/intruder/run"] button[data-arm-on-load]`, chromedp.ByQuery)},
		{"click launch", chromedp.Click(`#confirm-out form[hx-post="/ui2/intruder/run"] button[data-arm-on-load]`, chromedp.ByQuery)},
		// The re-render either links the finished attack's results or names the refusal. This
		// wait carries its own budget so a failure can dump the page state: a native submit
		// (405 page, #rows gone) and an htmx-swapped refusal read very differently.
		{"wait outcome", chromedp.ActionFunc(func(c context.Context) error {
			wc, cancel := context.WithTimeout(c, 15*time.Second)
			defer cancel()
			if err := chromedp.Run(wc, chromedp.WaitVisible(`#rows a[href*="/results"], #rows [role="alert"]`, chromedp.ByQuery)); err != nil {
				var href, dump string
				_ = chromedp.Run(c, chromedp.Location(&href))
				_ = chromedp.Run(c, chromedp.OuterHTML(`body`, &dump, chromedp.ByQuery))
				return fmt.Errorf("%v | location: %s | body: %.800s", err, href, dump)
			}
			return nil
		})},
		{"read rows", chromedp.Text(`#rows`, &results, chromedp.ByQuery)},
		{"click results", chromedp.Click(`#rows a[href*="/results"]`, chromedp.ByQuery)},
		{"settle", chromedp.Sleep(2 * time.Second)},
		{"read body", chromedp.Text(`body`, &results, chromedp.ByQuery)},
	}
	start := time.Now()
	for _, st := range stages {
		if err := chromedp.Run(ctx, st.act); err != nil {
			t.Fatalf("stage %q (%.1fs in): %v", st.name, time.Since(start).Seconds(), err)
		}
		t.Logf("stage %q ok (%.1fs in)", st.name, time.Since(start).Seconds())
	}
	if strings.Contains(results, "role=") || strings.Contains(results, "refused") && !strings.Contains(results, "view results") {
		t.Fatalf("the launch was refused in the browser: %.400s", results)
	}
	// The payloads were spliced into the query string, so the sent requests' paths name them,
	// and the victim's 200 says the dispatch really left the process.
	if !strings.Contains(results, "admin") {
		t.Fatalf("results page does not show the attack's sent requests: %.300s", results)
	}
}

// TestUI2CopyButtonReportsHonesty: the copy button must say Copied only when the copy
// actually happened — a rejected clipboard.writeText or a false execCommand means the
// operator still has to select the text, and the button has to say so.
func TestUI2CopyButtonReportsHonesty(t *testing.T) {
	s := newTestServer()
	srv := httptest.NewServer(s.mux)
	t.Cleanup(srv.Close)

	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("no-sandbox", true))
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, 30*time.Second)
	defer cancelTimeout()

	scenarios := []struct {
		name, stub, want string
	}{
		// navigator.clipboard is an accessor on the prototype: plain assignment is silently
		// ignored, so stub with defineProperty or the real (denied) headless clipboard answers.
		{"clipboard resolves", `Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: function () { return Promise.resolve(); } } });`, "Copied"},
		{"clipboard rejects", `Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: function () { return Promise.reject(new Error("denied")); } } });`, "Select text"},
		{"execCommand false", `Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined }); document.execCommand = function () { return false; };`, "Select text"},
		{"execCommand true", `Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined }); document.execCommand = function () { return true; };`, "Copied"},
	}
	if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL+"/ui2/dashboard")); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	for _, sc := range scenarios {
		var label string
		err := chromedp.Run(ctx,
			chromedp.Evaluate(sc.stub+`
			  var old = document.getElementById('probe-copy'); if (old) old.remove();
			  var b = document.createElement('button');
			  b.id = 'probe-copy'; b.className = 'copy-btn';
			  b.setAttribute('data-copy', 'probe-address');
			  b.textContent = 'Copy';
			  document.body.appendChild(b);
			  'ok'`, nil),
			chromedp.Evaluate(`document.getElementById('probe-copy').click(); 'ok'`, nil),
			chromedp.Poll(`(function(){var b=document.getElementById('probe-copy'); return b && b.textContent !== 'Copy';})()`, nil, chromedp.WithPollingInterval(50*time.Millisecond)),
			chromedp.Evaluate(`document.getElementById('probe-copy').textContent`, &label),
		)
		if err != nil {
			t.Fatalf("%s: %v", sc.name, err)
		}
		if label != sc.want {
			t.Errorf("%s: label %q, want %q", sc.name, label, sc.want)
		}
	}
}

// TestUI2MobileTapToExpandTruncatedCell: at a 390px viewport tables use fixed layout
// and cells truncate with an ellipsis. Tapping a truncated cell of the SELECTED row
// must expand it in place (full content wraps); tapping again collapses it. Taps on
// non-truncated cells and on unselected rows must not expand anything.
func TestUI2MobileTapToExpandTruncatedCell(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s,
		"GET /a/rather/long/path/that/will/truncate?with=query HTTP/1.1\r\nHost: a-very-long-hostname-that-truncates.example:18098\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok")
	srv := httptest.NewServer(s.mux)
	t.Cleanup(srv.Close)

	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("no-sandbox", true))
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, 30*time.Second)
	defer cancelTimeout()

	var probe struct {
		TruncatedIdx int  `json:"ti"`
		Selected     bool `json:"sel"`
		Expanded     bool `json:"exp"`
		Wrapped      bool `json:"wr"`
		Collapsed    bool `json:"col"`
	}
	err := chromedp.Run(ctx,
		chromedp.EmulateViewport(390, 844),
		chromedp.Navigate(srv.URL+"/ui2/history"),
		chromedp.WaitReady(`#rows-body tr`),
		// First tap selects the row.
		chromedp.Evaluate(`document.querySelector('#rows-body tr').click(); 'ok'`, nil),
		chromedp.Poll(`document.querySelector('#rows-body tr.selected') !== null`, nil, chromedp.WithPollingInterval(50*time.Millisecond)),
		// Tap the first truncated cell of the selected row.
		chromedp.Evaluate(`(function(){
			const tr = document.querySelector('#rows-body tr.selected');
			const tds = [...tr.querySelectorAll('td')];
			const i = tds.findIndex(td => td.scrollWidth > td.clientWidth + 1);
			if (i < 0) return ({ti:-1});
			tds[i].click();
			const td = tds[i];
			const expanded = td.classList.contains('cell-x');
			const wrapped = getComputedStyle(td).whiteSpace === 'normal';
			if (expanded) td.click();
			return ({ti:i, sel:true, exp:expanded, wr:wrapped, col:!td.classList.contains('cell-x')});
		})()`, &probe),
	)
	if err != nil {
		t.Fatalf("browser run: %v", err)
	}
	if probe.TruncatedIdx < 0 {
		t.Fatalf("no truncated cell found at 390px - the affordance has nothing to work on")
	}
	if !probe.Selected || !probe.Expanded || !probe.Wrapped || !probe.Collapsed {
		t.Errorf("tap-to-expand misbehaved: %+v", probe)
	}
}
