package domexec

import (
	"context"
	"fmt"
	"net/url"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// Probe runs supplied instrumentation in a dedicated session tab. The caller
// owns this session exclusively and supplies a scope gate. Unlike the ordinary
// crawl renderer it adds response-header CSP before any document script runs:
// no workers, frames, objects or popups. Those surfaces are NOT exercised.
// Reuses the crawl's isolated context, proxy and full-URL Fetch gate.
func (s *Session) Probe(ctx context.Context, targetURL, preload, collect string) (string, error) {
	if s.gate == nil {
		return "", fmt.Errorf("probe requires an explicit scope gate")
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	if err := s.gate.AllowURL(u); err != nil {
		return "", err
	}
	s.restrictedProbe = true
	tab, cancel, err := s.newTab(ctx, s.b.opts.resolvedTimeout())
	if err != nil {
		return "", err
	}
	defer cancel()
	var result string
	err = chromedp.Run(tab, network.SetBypassServiceWorker(true), chromedp.ActionFunc(func(ctx context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(preload).Do(ctx)
		return err
	}), chromedp.Navigate(targetURL))
	// A page navigating to a refused URL can still have useful refusal evidence.
	if err != nil {
		return "", err
	}
	waitForSettle(tab, RenderOptions{MaxWait: DefaultMaxRenderWait}.withDefaults())
	err = chromedp.Run(tab, chromedp.Evaluate(collect, &result))
	return result, err
}
