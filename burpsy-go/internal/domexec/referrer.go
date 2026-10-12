package domexec

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// CrossOriginSend is one request a loaded page tried to make to an origin other than its own, as the
// browser built it: the Referer it attached is what that origin would have been told about the page.
type CrossOriginSend struct {
	URL          string
	Referer      string
	ResourceType string
}

// ObserveCrossOriginReferers loads pageURL in a fresh tab, lets its scripts run for settle, and reports
// every request the page made to another origin together with the Referer header the browser attached
// to it — the question a Referrer-Policy is the answer to, asked of the browser rather than of the
// policy text.
//
// Nothing is sent to another origin: every request is paused at the request stage, a cross-origin one
// is recorded and then FAILED there, and only a same-origin request that allowSameOrigin accepts (the
// caller's scope check) is let through. data:, blob: and about: URLs never leave the machine and are
// let through. A page that never loads is an error, never an empty result.
func (b *Browser) ObserveCrossOriginReferers(ctx context.Context, pageURL string, settle time.Duration,
	allowSameOrigin func(*url.URL) bool) ([]CrossOriginSend, error) {

	page, err := url.Parse(pageURL)
	if err != nil || (page.Scheme != "http" && page.Scheme != "https") {
		return nil, fmt.Errorf("domexec: %q is not an http(s) page", pageURL)
	}
	tabCtx, cancel, err := b.newTab(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	var mu sync.Mutex
	var sends []CrossOriginSend
	var pageLoaded bool
	chromedp.ListenTarget(tabCtx, func(ev any) {
		e, ok := ev.(*fetch.EventRequestPaused)
		if !ok || e.Request == nil {
			return
		}
		// A CDP command issued from inside a ListenTarget callback deadlocks the event loop that
		// delivers it, so the decision runs in its own goroutine (as installFetchGate's does).
		go func() {
			c := chromedp.FromContext(tabCtx)
			if c == nil || c.Target == nil {
				return
			}
			exec := cdp.WithExecutor(tabCtx, c.Target)
			u, perr := url.Parse(e.Request.URL)
			if perr == nil && (u.Scheme == "data" || u.Scheme == "blob" || u.Scheme == "about") {
				_ = fetch.ContinueRequest(e.RequestID).Do(exec)
				return
			}
			if perr == nil && sameOrigin(u, page) && allowSameOrigin != nil && allowSameOrigin(u) {
				if e.ResourceType == network.ResourceTypeDocument {
					mu.Lock()
					pageLoaded = true
					mu.Unlock()
				}
				_ = fetch.ContinueRequest(e.RequestID).Do(exec)
				return
			}
			referer := ""
			for k, v := range e.Request.Headers {
				if strings.EqualFold(k, "Referer") {
					referer = fmt.Sprint(v)
				}
			}
			mu.Lock()
			sends = append(sends, CrossOriginSend{URL: e.Request.URL, Referer: referer, ResourceType: string(e.ResourceType)})
			mu.Unlock()
			_ = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(exec)
		}()
	})
	if err := chromedp.Run(tabCtx,
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{{URLPattern: "*", RequestStage: fetch.RequestStageRequest}}),
		chromedp.Navigate(pageURL),
	); err != nil {
		return nil, fmt.Errorf("domexec: loading %s: %w", RedactURL(pageURL), err)
	}
	select {
	case <-time.After(settle):
	case <-tabCtx.Done():
	}
	mu.Lock()
	defer mu.Unlock()
	if !pageLoaded {
		return nil, fmt.Errorf("domexec: %s was never let through to load", RedactURL(pageURL))
	}
	return append([]CrossOriginSend(nil), sends...), nil
}

// sameOrigin compares scheme, host and effective port.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}
