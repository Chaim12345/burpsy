package main

// xsschallenge measures whether burpsy's XSS checks find XSS they were never shown.
//
// Three phases, in this order, because the order is what makes the result mean anything:
//
//  1. GROUND TRUTH. Every case is loaded in a real headless Chrome with its exploit, and the run
//     asks the page whether window.__pwned got set. A "vulnerable" case whose exploit does not fire
//     is a broken fixture and is reported as such - never as a scanner miss. A "safe" case whose
//     exploit DOES fire is also a broken fixture. This phase exists because the two most expensive
//     mistakes in this project have both been fixtures that manufactured their own answer.
//  2. BLIND SCAN. The scanner is handed one captured request per endpoint carrying a benign value,
//     exactly what a proxy would have recorded, and is told nothing else. No row names, no hints,
//     no manifest. Every check family is switched on - that is configuration, not tuning.
//  3. SCORECARD. Per endpoint: was any Cross-site scripting row reported? Detected / missed for the
//     vulnerable twenty, clean / false-positive for the safe six.
//
// Run it: go run ./cmd/xsschallenge
// It is not part of the test suite and contributes to no coverage number.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	cdppage "github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
)

func main() {
	verbose := flag.Bool("v", false, "print every row each endpoint reported, not just XSS rows")
	flag.Parse()

	srv := httptest.NewServer(challengeMux())
	defer srv.Close()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		fail("split target address: %v", err)
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		fail("parse target port: %v", err)
	}
	port := uint16(port64)

	all := cases()
	fmt.Printf("challenge target on %s - %d endpoints (%d intended vulnerable, %d intended safe)\n\n",
		srv.URL, len(all), countIf(all, func(c xcase) bool { return c.vulnerable }),
		countIf(all, func(c xcase) bool { return !c.vulnerable }))

	// ---- phase 1: ground truth in a real browser ----
	fmt.Println("== phase 1: proving each case in a real browser ==")
	truth, broken := proveAll(srv.URL, all)
	if len(broken) > 0 {
		fmt.Printf("\n%d fixture(s) do not behave as declared:\n", len(broken))
		for _, b := range broken {
			fmt.Printf("  BROKEN %-24s %s\n", b.name, b.why)
		}
		fmt.Println("\nRefusing to score: a broken fixture cannot distinguish a scanner miss from a")
		fmt.Println("target that was never vulnerable. Fix the fixture and re-run.")
		os.Exit(1)
	}
	fmt.Printf("all %d cases behave exactly as declared\n\n", len(all))

	// ---- phase 2: blind scan ----
	fmt.Println("== phase 2: blind scan ==")
	found := blindScan(srv.URL, host, port, all)

	// ---- phase 3: scorecard ----
	fmt.Println("\n== phase 3: scorecard ==")
	report(all, truth, found, *verbose)
}

type brokenCase struct{ name, why string }

// proveAll loads every case with its exploit and records whether the marker fired.
func proveAll(base string, all []xcase) (map[string]bool, []brokenCase) {
	// Headless by default, headed only when explicitly asked.
	//
	// The previous comment here had this backwards and the recipe it prescribed could not score. It
	// claimed a headless window is never activated so autofocus cannot deliver a focus event, and that
	// a DISPLAY was therefore required. Measured, both ways, on the real fixtures: headless reports
	// document.activeElement == INPUT and the handler fires; headed on bare Xvfb - and on Xvfb with a
	// window manager - reports BODY and it does not, even though document.hasFocus() is true. So the
	// display was never the mechanism, and anyone following the old recipe hit the same refusal the
	// instrument exists to prevent.
	//
	// Rather than trade one environment assumption for another, prove() now focuses the element it
	// needs instead of hoping the window does it, so both modes work. BURPSY_XSS_HEADED=1 is kept for
	// watching a run.
	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.NoSandbox)
	if os.Getenv("BURPSY_XSS_HEADED") == "1" {
		display := os.Getenv("DISPLAY")
		if display == "" {
			fail("BURPSY_XSS_HEADED=1 needs a DISPLAY")
		}
		opts = append(opts, chromedp.Flag("headless", false), chromedp.Env("DISPLAY="+display))
		fmt.Printf("  headed on DISPLAY=%s (explicitly requested)\n", display)
	} else {
		fmt.Println("  headless (set BURPSY_XSS_HEADED=1 with a DISPLAY to watch a run)")
	}
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	truth := map[string]bool{}
	var broken []brokenCase
	for _, c := range all {
		fired, err := prove(browserCtx, base, c)
		if err != nil {
			broken = append(broken, brokenCase{c.name, "could not be driven: " + err.Error()})
			continue
		}
		truth[c.name] = fired
		switch {
		case c.vulnerable && !fired:
			broken = append(broken, brokenCase{c.name,
				"declared vulnerable, but its exploit did not execute - the payload or the sink is wrong"})
		case !c.vulnerable && fired:
			broken = append(broken, brokenCase{c.name,
				"declared safe, but its exploit DID execute - it is not a safe endpoint"})
		default:
			mark := "exploitable"
			if !c.vulnerable {
				mark = "not exploitable"
			}
			fmt.Printf("  %-24s %s\n", c.name, mark)
		}
	}
	return truth, broken
}

// prove drives one case to its exploit and reports whether window.__pwned was set.
func prove(parent context.Context, base string, c xcase) (bool, error) {
	ctx, cancel := chromedp.NewContext(parent)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, 30*time.Second)
	defer cancelTimeout()

	target := base + c.path
	var acts []chromedp.Action

	switch {
	case c.fragment:
		target = base + c.path + "#" + url.PathEscape(c.exploit)
	case c.stored:
		// Plant over HTTP, then load the page that renders it.
		if _, err := http.Get(base + c.path + "?" + c.param + "=" + url.QueryEscape(c.exploit)); err != nil {
			return false, fmt.Errorf("plant: %w", err)
		}
		target = base + c.viewPath
	case c.header != "":
		acts = append(acts, setHeader(c.header, c.exploit))
	case c.cookie != "":
		// Set the cookie from a benign page on the same origin, then load the reflecting page.
		acts = append(acts,
			chromedp.Navigate(base+"/s/escaped?q=benign"),
			chromedp.ActionFunc(func(ctx context.Context) error {
				return chromedp.Evaluate(fmt.Sprintf("document.cookie=%q",
					c.cookie+"="+c.exploit+"; path=/"), nil).Do(ctx)
			}),
		)
	default:
		target = base + c.path + "?" + c.param + "=" + url.QueryEscape(c.exploit)
	}

	var fired bool
	acts = append(acts,
		chromedp.Navigate(target),
		// Activate the tab. Xvfb runs no window manager, so the browser window is never made active
		// on its own, and an inactive document does not deliver the focus event that autofocus is
		// supposed to produce. Without this the attribute-context payloads fail for a reason that has
		// nothing to do with the application being tested.
		chromedp.ActionFunc(func(ctx context.Context) error { return cdppage.BringToFront().Do(ctx) }),
		// The srcdoc case executes inside a child document, and an event handler may need a tick,
		// so settle before asking.
		chromedp.Sleep(700*time.Millisecond),
	)
	// Deliver focus explicitly. autofocus depends on the document being the active one, which varies
	// by mode and window manager; focusing the element the payload targets does not. A payload that
	// needs a click still gets a real one below.
	acts = append(acts, chromedp.ActionFunc(func(ctx context.Context) error {
		_ = chromedp.Evaluate(`(function(){var e=document.querySelector('[autofocus]');if(e&&e.focus)e.focus();})()`, nil).Do(ctx)
		return nil
	}), chromedp.Sleep(200*time.Millisecond))

	if c.clickSelector != "" {
		// A real click on a real display. The href sink genuinely requires one, and pretending
		// otherwise would either drop the case or fake its proof.
		acts = append(acts,
			chromedp.WaitVisible(c.clickSelector, chromedp.ByQuery),
			chromedp.Click(c.clickSelector, chromedp.ByQuery),
			chromedp.Sleep(700*time.Millisecond),
		)
	}
	acts = append(acts, chromedp.Evaluate(`window.__pwned === 1`, &fired))
	if err := chromedp.Run(ctx, acts...); err != nil {
		// An Evaluate against a page that navigated away is not a fixture problem worth aborting
		// for; report it as not-fired and let the declared/observed comparison speak.
		return false, err
	}
	return fired, nil
}

// setHeader makes the tab send one request header.
//
// User-Agent is special: SetExtraHTTPHeaders does not reliably override it, because Chrome sets it
// from its own emulation state. Everything else goes through the network domain.
func setHeader(name, value string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		if strings.EqualFold(name, "User-Agent") {
			return emulation.SetUserAgentOverride(value).Do(ctx)
		}
		if err := network.Enable().Do(ctx); err != nil {
			return err
		}
		return network.SetExtraHTTPHeaders(network.Headers{name: value}).Do(ctx)
	})
}

// blindScan seeds one benign request per endpoint and audits each with every family enabled.
func blindScan(base, host string, port uint16, all []xcase) map[string]map[string]*scanner.Finding {
	store := core.NewTrafficStore()
	client := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	type seeded struct {
		c  xcase
		id core.ExchangeID
	}
	var seeds []seeded
	for _, c := range all {
		path := c.path
		if c.param != "" {
			// The benign value a real user would have sent. This is the ONLY thing the scanner is
			// given: a parameter that exists, holding something harmless.
			path = c.path + "?" + c.param + "=hello"
		}
		id, err := seedOne(store, client, base, host, port, c, path)
		if err != nil {
			fmt.Printf("  seed %-22s FAILED: %v\n", c.name, err)
			continue
		}
		seeds = append(seeds, seeded{c, id})
	}
	fmt.Printf("  seeded %d captured request(s), each carrying a benign value\n", len(seeds))

	cfg := blindConfig()
	scan := scanner.NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(&sender.SenderConfig{Timeout: 20 * time.Second, TLSVerify: false})).
		WithStoredLedger(scanner.NewStoredLedger()).
		WithBrowserProvider(scanner.NewLazyBrowserProvider(domexec.Options{})).
		WithConfig(cfg)
	defer func() { _ = scan.CloseCapabilities() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	out := map[string]map[string]*scanner.Finding{}
	for _, s := range seeds {
		byRow := map[string]*scanner.Finding{}
		_, findings := scan.AuditWithin(ctx, s.id, scan.AuditConfig())
		for _, f := range findings {
			if f != nil {
				byRow[f.Name] = f
			}
		}
		out[s.c.name] = byRow
	}

	// The deferred phase is where a stored flow can surface: the canary is planted during an audit,
	// so no response that audit saw could contain it.
	deferred, completion := scan.FinishScan(ctx)
	if completion.RefetchError != "" {
		fmt.Printf("  deferred re-fetch error: %s\n", completion.RefetchError)
	}
	if completion.RenderError != "" {
		fmt.Printf("  deferred render error: %s\n", completion.RenderError)
	}
	fmt.Printf("  deferred phase: %s\n", completion.Render.Summary())
	if len(deferred) > 0 {
		// A deferred finding names the exchange it was proven at, which may not be the one that
		// planted it; attribute by path so the scorecard can find it.
		for _, f := range deferred {
			if f == nil {
				continue
			}
			for _, s := range seeds {
				if strings.Contains(f.Evidence, s.c.name) || s.c.stored {
					out[s.c.name][f.Name] = f
				}
			}
		}
	}
	return out
}

// blindConfig turns on every family. Enabling checks is configuration; it tells the scanner what to
// look for, not where to look or what the answer is.
func blindConfig() *scanner.ScanConfig {
	return &scanner.ScanConfig{
		MaxConcurrency:          4,
		Timeout:                 5 * time.Minute,
		CheckSqli:               true,
		CheckXss:                true,
		CheckPathTraversal:      true,
		CheckJwtWeak:            true,
		CheckJSVulns:            true,
		CheckHeaders:            true,
		CheckCachePoisoning:     true,
		CheckReflectionProbes:   true,
		CheckHostDiscovery:      true,
		CheckResponseDependence: true,
		CheckPassivePosture:     true,
		CheckPassiveAnalysis:    true,
		CheckActiveInjection:    true,
		CheckExtendedActive:     true,
		CheckDOM:                true,
		CheckStored:             true,
		PendingDeadline:         5 * time.Second,
	}
}

func seedOne(store *core.TrafficStore, client *http.Client, base, host string, port uint16,
	c xcase, path string) (core.ExchangeID, error) {
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		return 0, err
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, err
	}

	var rawReq strings.Builder
	fmt.Fprintf(&rawReq, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&rawReq, "Host: %s\r\n", net.JoinHostPort(host, strconv.Itoa(int(port))))
	rawReq.WriteString("User-Agent: Mozilla/5.0 (challenge)\r\n")
	if c.cookie != "" {
		fmt.Fprintf(&rawReq, "Cookie: %s=hello\r\n", c.cookie)
	}
	rawReq.WriteString("\r\n")

	var rawResp strings.Builder
	fmt.Fprintf(&rawResp, "HTTP/1.1 %d %s\r\n", res.StatusCode, http.StatusText(res.StatusCode))
	for k, vs := range res.Header {
		for _, v := range vs {
			fmt.Fprintf(&rawResp, "%s: %s\r\n", k, v)
		}
	}
	rawResp.WriteString("\r\n")
	rawResp.Write(body)

	reqID, err := store.Put([]byte(rawReq.String()), core.DirectionRequest)
	if err != nil {
		return 0, err
	}
	respID, err := store.Put([]byte(rawResp.String()), core.DirectionResponse)
	if err != nil {
		return 0, err
	}
	ex := &core.Exchange{
		Request: reqID, Response: &respID,
		Host: host, Port: port, TLS: false,
		Method: http.MethodGet, Path: path,
	}
	store.AddExchange(ex)
	return ex.ID, nil
}

// report prints the scorecard and exits non-zero when a safe endpoint was reported.
func report(all []xcase, truth map[string]bool, found map[string]map[string]*scanner.Finding, verbose bool) {
	var detected, missed, clean, falsePos []xcase
	for _, c := range all {
		hit := xssRows(found[c.name])
		switch {
		case c.vulnerable && len(hit) > 0:
			detected = append(detected, c)
		case c.vulnerable:
			missed = append(missed, c)
		case len(hit) > 0:
			falsePos = append(falsePos, c)
		default:
			clean = append(clean, c)
		}
	}

	fmt.Printf("\nDETECTED %d of %d exploitable endpoints\n", len(detected), len(detected)+len(missed))
	for _, c := range detected {
		fmt.Printf("  hit   %-24s %s\n", c.name, strings.Join(xssRows(found[c.name]), ", "))
	}
	fmt.Printf("\nMISSED %d exploitable endpoints - each is proven exploitable in a browser\n", len(missed))
	for _, c := range missed {
		other := otherRows(found[c.name])
		note := "no rows at all"
		if len(other) > 0 {
			note = "reported instead: " + strings.Join(other, ", ")
		}
		fmt.Printf("  MISS  %-24s %s\n        %s\n        %s\n", c.name, note, c.context, "exploit: "+c.exploit)
	}
	fmt.Printf("\nFALSE POSITIVES %d of %d safe endpoints\n", len(falsePos), len(falsePos)+len(clean))
	for _, c := range falsePos {
		fmt.Printf("  FP    %-24s %s\n        %s\n", c.name, strings.Join(xssRows(found[c.name]), ", "), c.context)
		// The evidence text names the payload and the bit that confirmed it, which is what turns a
		// false positive from a number into something fixable.
		for _, name := range xssRows(found[c.name]) {
			if f := found[c.name][name]; f != nil {
				fmt.Printf("        evidence: %s\n", f.Evidence)
			}
		}
	}
	for _, c := range clean {
		fmt.Printf("  quiet %-24s %s\n", c.name, c.context)
	}

	if verbose {
		fmt.Println("\n-- every row reported, per endpoint --")
		for _, c := range all {
			rows := allRows(found[c.name])
			fmt.Printf("  %-24s %s\n", c.name, strings.Join(rows, ", "))
		}
	}

	total := len(detected) + len(missed)
	fmt.Printf("\nRESULT  detection %d/%d", len(detected), total)
	if total > 0 {
		fmt.Printf(" (%.0f%%)", 100*float64(len(detected))/float64(total))
	}
	fmt.Printf("   false positives %d/%d\n", len(falsePos), len(falsePos)+len(clean))
}

func xssRows(rows map[string]*scanner.Finding) []string {
	var out []string
	for name := range rows {
		if strings.Contains(strings.ToLower(name), "cross-site scripting") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func otherRows(rows map[string]*scanner.Finding) []string {
	var out []string
	for name := range rows {
		if !strings.Contains(strings.ToLower(name), "cross-site scripting") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func allRows(rows map[string]*scanner.Finding) []string {
	var out []string
	for name := range rows {
		out = append(out, name)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return []string{"(nothing)"}
	}
	return out
}

func countIf(all []xcase, pred func(xcase) bool) int {
	n := 0
	for _, c := range all {
		if pred(c) {
			n++
		}
	}
	return n
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "xsschallenge: "+format+"\n", args...)
	os.Exit(1)
}
