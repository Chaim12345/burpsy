package domexec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// SourceKind identifies one of the DOM sources the declined catalog's
// "(reflected DOM-based)" / "(DOM-based)" rows are about: data an attacker
// controls without touching the server, that a vulnerable page's own script
// reads back out of the browser and feeds into a sink.
type SourceKind int

const (
	SourceLocationHash SourceKind = iota
	SourceLocationSearch
	SourceReferrer
	SourceWindowName
	SourcePostMessage
	// SourceStored is not a browser-readable source at all: it is a value the application
	// persisted earlier and now serves back to its own page. It exists so a stored flow's
	// observation can say where the data came from, and it is deliberately not plantable —
	// plantSource refuses it, because the planting happened over HTTP long before this load.
	SourceStored
)

func (s SourceKind) String() string {
	switch s {
	case SourceLocationHash:
		return "location.hash"
	case SourceLocationSearch:
		return "location.search"
	case SourceReferrer:
		return "document.referrer"
	case SourceWindowName:
		return "window.name"
	case SourcePostMessage:
		return "postMessage"
	case SourceStored:
		return "stored application data"
	default:
		return fmt.Sprintf("SourceKind(%d)", int(s))
	}
}

// SinkKind identifies a dangerous runtime sink. Each maps to at least one
// declined catalog row family: SinkEval/SinkFunctionCtor/SinkDocumentWrite/
// SinkInnerHTML/SinkSetTimeoutString/SinkScriptSrc/SinkJQueryHtml to DOM-based
// XSS; SinkLocationAssign to DOM-based open redirection; SinkWebSocketURL to
// WebSocket URL poisoning; SinkLocalStorage/SinkSessionStorage to HTML5
// storage manipulation; SinkDocumentDomain to document domain manipulation;
// SinkCookie to cookie manipulation; SinkXHROpen and SinkPostMessage to DOM
// data manipulation / client-side request forgery families.
type SinkKind int

const (
	SinkEval SinkKind = iota
	SinkFunctionCtor
	SinkInnerHTML
	SinkDocumentWrite
	SinkLocationAssign
	SinkSetTimeoutString
	SinkScriptSrc
	SinkJQueryHtml
	SinkLocalStorage
	SinkSessionStorage
	SinkPostMessage
	SinkWebSocketURL
	SinkDocumentDomain
	SinkXHROpen
	SinkCookie
	// Sinks below were added to close catalog rows whose family had no instrumented sink.
	SinkWebSQL
	SinkXPathEvaluate
	SinkJSONParse
	SinkAnchorHref
	SinkRegExpCtor
	SinkFileRead
	SinkPrototypePollution
	// SinkAjaxHeader is XMLHttpRequest.setRequestHeader's value argument. It exists because
	// "Ajax request header manipulation" was previously observed at SinkXHROpen — the URL — which
	// is a different defect that happens to be reachable from the same object. A flow that taints
	// only a header value never touches the URL, so the row could report nothing while being
	// exactly what it is named for.
	SinkAjaxHeader
)

func (s SinkKind) String() string {
	switch s {
	case SinkEval:
		return "eval"
	case SinkFunctionCtor:
		return "Function"
	case SinkInnerHTML:
		return "innerHTML"
	case SinkDocumentWrite:
		return "document.write"
	case SinkLocationAssign:
		return "location"
	case SinkSetTimeoutString:
		return "setTimeout(string)"
	case SinkScriptSrc:
		return "script.src"
	case SinkJQueryHtml:
		return "jQuery.html"
	case SinkLocalStorage:
		return "localStorage"
	case SinkSessionStorage:
		return "sessionStorage"
	case SinkPostMessage:
		return "postMessage"
	case SinkWebSocketURL:
		return "WebSocket(url)"
	case SinkDocumentDomain:
		return "document.domain"
	case SinkXHROpen:
		return "XMLHttpRequest.open"
	case SinkCookie:
		return "document.cookie"
	case SinkWebSQL:
		return "SQLTransaction.executeSql"
	case SinkXPathEvaluate:
		return "document.evaluate"
	case SinkJSONParse:
		return "JSON.parse"
	case SinkAnchorHref:
		return "anchor.href"
	case SinkRegExpCtor:
		return "RegExp"
	case SinkFileRead:
		return "FileReader.read*"
	case SinkPrototypePollution:
		return "Object.prototype"
	case SinkAjaxHeader:
		return "XMLHttpRequest.setRequestHeader"
	default:
		return fmt.Sprintf("SinkKind(%d)", int(s))
	}
}

// sinkTags maps the JS-side tag string instrumentationJS records onto a
// SinkKind. It is the decode counterpart of the "sink" field
// instrumentationJS pushes onto window.__burpsyTaint; keep the two in sync.
//
// SinkLocationAssign has no entry here on purpose: see the package doc
// comment and the instrumentationJS doc comment below for why bare
// `location = x` cannot be observed this way, and getNavigationObservations
// for how it is observed instead.
var sinkTags = map[string]SinkKind{
	"eval":                 SinkEval,
	"function-ctor":        SinkFunctionCtor,
	"innerHTML":            SinkInnerHTML,
	"outerHTML":            SinkInnerHTML,
	"document-write":       SinkDocumentWrite,
	"settimeout-string":    SinkSetTimeoutString,
	"script-src":           SinkScriptSrc,
	"jquery-html":          SinkJQueryHtml,
	"localStorage":         SinkLocalStorage,
	"sessionStorage":       SinkSessionStorage,
	"postmessage":          SinkPostMessage,
	"websocket-url":        SinkWebSocketURL,
	"document-domain":      SinkDocumentDomain,
	"xhr-open":             SinkXHROpen,
	"cookie":               SinkCookie,
	"websql-executesql":    SinkWebSQL,
	"document-evaluate":    SinkXPathEvaluate,
	"json-parse":           SinkJSONParse,
	"anchor-href":          SinkAnchorHref,
	"regexp-ctor":          SinkRegExpCtor,
	"file-read":            SinkFileRead,
	"prototype-pollution":  SinkPrototypePollution,
	"xhr-setrequestheader": SinkAjaxHeader,
}

// Observation is one canary sighting: attacker-controlled data (Canary),
// planted via Source, that reached Sink at runtime with argument Argument.
// StackTrace is the JS call stack captured at the moment of the sink call,
// useful for a human triaging *where* in page script the flow occurred.
type Observation struct {
	Sink       SinkKind
	Source     SourceKind
	Canary     string
	Argument   string
	StackTrace string
}

// instrumentationJS is injected via page.AddScriptToEvaluateOnNewDocument, so
// it runs before any script the target page itself contains. It wraps a
// fixed set of dangerous sinks so that any call whose stringified argument
// contains the observation's canary is recorded to window.__burpsyTaint,
// then always calls through to the original implementation — an
// instrumented page that stops working partway through observes nothing for
// the rest of its script, which would silently hide real findings.
//
// # Coverage and its limit
//
// This wraps exactly the APIs named in sinkTags above (plus WebSocket and
// Function, handled as constructor replacements rather than property
// setters). A page that reaches a dangerous sink through an API this list
// does not cover — a bespoke templating engine's own unsafe-HTML helper, for
// instance — produces zero observations. That is a false negative, not
// evidence of safety; see the package doc comment.
//
// # Why `location = x` is not wrapped here
//
// Object.defineProperty(Location.prototype, 'href', ...) succeeds (that
// descriptor is configurable) but is dead code in every Chromium build
// tested: window.location's own href/assign/replace/reload are non-
// configurable *own* accessor properties on the Location instance itself,
// which JS property lookup finds before ever consulting the prototype, so
// they permanently shadow any prototype-level override. window.location
// itself is [Unforgeable] on Window and cannot be redefined at all
// (Object.defineProperty on it throws "Cannot redefine property: location").
// This was confirmed empirically, not assumed: overriding
// Location.prototype.href and then executing both `location.href = x` and
// bare `location = x` produced zero hook firings in both cases. DOM-based
// open redirection (SinkLocationAssign) is therefore not observed via this
// script at all — ObserveTaint detects it independently, from the CDP
// frame-navigation events the browser emits when a script-driven redirect
// actually happens. That is strictly stronger evidence than an intercepted
// call would be: it proves the browser really navigated, not merely that a
// sink was reached.
//
// # Defensiveness
//
// Every hook installs inside its own try/catch, and record() itself never
// throws, so one hook failing (an API absent in a given Chrome build, say)
// cannot disable the others or break the page.
const instrumentationJS = `
(function() {
  window.__burpsyTaint = [];
  function record(sink, arg) {
    try {
      window.__burpsyTaint.push({
        sink: sink,
        arg: String(arg),
        stack: (new Error()).stack || ''
      });
    } catch (e) {}
  }
  function wrapMethod(obj, name, sink, argIndex) {
    try {
      var orig = obj[name];
      if (typeof orig !== 'function') return;
      obj[name] = function() {
        try { record(sink, arguments[argIndex]); } catch (e) {}
        return orig.apply(this, arguments);
      };
    } catch (e) {}
  }
  function wrapSetter(proto, prop, sink) {
    try {
      var orig = Object.getOwnPropertyDescriptor(proto, prop);
      if (!orig || !orig.set) return;
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: orig.enumerable,
        get: orig.get,
        set: function(v) {
          try { record(sink, v); } catch (e) {}
          return orig.set.call(this, v);
        }
      });
    } catch (e) {}
  }
  wrapMethod(window, 'eval', 'eval', 0);
  try {
    var OrigFunction = window.Function;
    var wrappedFunction = function() {
      try { record('function-ctor', Array.prototype.join.call(arguments, ',')); } catch (e) {}
      return OrigFunction.apply(this, arguments);
    };
    wrappedFunction.prototype = OrigFunction.prototype;
    window.Function = wrappedFunction;
  } catch (e) {}
  wrapMethod(window, 'setTimeout', 'settimeout-string', 0);
  wrapMethod(Document.prototype, 'write', 'document-write', 0);
  wrapSetter(Element.prototype, 'innerHTML', 'innerHTML');
  wrapSetter(Element.prototype, 'outerHTML', 'outerHTML');
  wrapSetter(HTMLScriptElement.prototype, 'src', 'script-src');
  wrapSetter(Document.prototype, 'domain', 'document-domain');
  wrapSetter(Document.prototype, 'cookie', 'cookie');
  try {
    var origSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function(key, value) {
      try {
        var sink = (this === window.localStorage) ? 'localStorage' :
          (this === window.sessionStorage ? 'sessionStorage' : 'localStorage');
        record(sink, value);
      } catch (e) {}
      return origSetItem.call(this, key, value);
    };
  } catch (e) {}
  wrapMethod(window, 'postMessage', 'postmessage', 0);
  wrapMethod(XMLHttpRequest.prototype, 'open', 'xhr-open', 1);
  // Argument 1 is the header VALUE, not the name: a stored value smuggled into a header is the
  // "Ajax request header manipulation" defect, and it never touches the URL that xhr-open sees.
  wrapMethod(XMLHttpRequest.prototype, 'setRequestHeader', 'xhr-setrequestheader', 1);
  try {
    var OrigWebSocket = window.WebSocket;
    var wrappedWebSocket = function(url, protocols) {
      try { record('websocket-url', url); } catch (e) {}
      return (protocols === undefined) ? new OrigWebSocket(url) : new OrigWebSocket(url, protocols);
    };
    wrappedWebSocket.prototype = OrigWebSocket.prototype;
    window.WebSocket = wrappedWebSocket;
  } catch (e) {}
  try {
    if (window.jQuery && window.jQuery.fn && typeof window.jQuery.fn.html === 'function') {
      var origHtml = window.jQuery.fn.html;
      window.jQuery.fn.html = function(value) {
        if (arguments.length > 0) {
          try { record('jquery-html', value); } catch (e) {}
        }
        return origHtml.apply(this, arguments);
      };
    }
  } catch (e) {}
  // WebSQL: the Client-side SQL injection family's sink. Deprecated in Chrome but still
  // present behind a flag and still shipped by embedded WebViews, so a page that calls it
  // is exactly what that row is about.
  try {
    if (window.openDatabase) {
      var origOpenDatabase = window.openDatabase;
      window.openDatabase = function() {
        var db = origOpenDatabase.apply(this, arguments);
        try {
          if (db && typeof db.transaction === 'function') {
            var origTx = db.transaction;
            db.transaction = function(cb) {
              return origTx.call(this, function(tx) {
                try {
                  var origExec = tx.executeSql;
                  tx.executeSql = function(sql) {
                    try { record('websql-executesql', sql); } catch (e) {}
                    return origExec.apply(this, arguments);
                  };
                } catch (e) {}
                return cb(tx);
              });
            };
          }
        } catch (e) {}
        return db;
      };
    }
  } catch (e) {}
  // XPath: Client-side XPath injection.
  wrapMethod(Document.prototype, 'evaluate', 'document-evaluate', 0);
  // JSON.parse: Client-side JSON injection. Recorded on the argument, because the finding is
  // that attacker text is parsed as structure, not that parsing happened.
  wrapMethod(JSON, 'parse', 'json-parse', 0);
  // Anchor href: Link manipulation. Distinct from script.src, which is already wrapped.
  wrapSetter(HTMLAnchorElement.prototype, 'href', 'anchor-href');
  // RegExp built from tainted input: the Denial of service family's reachable sink, since a
  // pattern an attacker controls is the classic catastrophic-backtracking vector.
  try {
    var OrigRegExp = window.RegExp;
    var wrappedRegExp = function(pattern, flags) {
      try { record('regexp-ctor', pattern); } catch (e) {}
      return (flags === undefined) ? new OrigRegExp(pattern) : new OrigRegExp(pattern, flags);
    };
    wrappedRegExp.prototype = OrigRegExp.prototype;
    window.RegExp = wrappedRegExp;
  } catch (e) {}
  // Local file path manipulation: a tainted value reaching a file-reading API.
  try {
    if (window.FileReader) {
      wrapMethod(FileReader.prototype, 'readAsText', 'file-read', 0);
      wrapMethod(FileReader.prototype, 'readAsDataURL', 'file-read', 0);
    }
  } catch (e) {}
  // Object.prototype writes: Client-side prototype pollution observed in a real browser
  // rather than only in the goja tier.
  try {
    var origDefineProperty = Object.defineProperty;
    Object.defineProperty = function(target, prop, desc) {
      try {
        if (target === Object.prototype) { record('prototype-pollution', String(prop)); }
      } catch (e) {}
      return origDefineProperty.apply(this, arguments);
    };
  } catch (e) {}
})();
`

// taintRecord is the JSON shape instrumentationJS pushes onto
// window.__burpsyTaint; field names mirror the JS object exactly.
type taintRecord struct {
	Sink  string `json:"sink"`
	Arg   string `json:"arg"`
	Stack string `json:"stack"`
}

// jsString renders a Go string as a double-quoted JS string literal via JSON
// encoding, which is a valid (and safe against injection) JS literal syntax.
func jsString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// plantSource returns the URL to navigate to and, for SourceReferrer, the
// Referer value CDP should send with that navigation. SourceWindowName and
// SourcePostMessage need extra actions beyond a URL/header and are planted by
// ObserveTaint itself; plantSource just validates the source kind is one this
// harness knows how to plant at all.
func plantSource(targetURL string, source SourceKind, canary string) (plantedURL, referrer string, err error) {
	switch source {
	case SourceLocationHash:
		return targetURL + "#" + canary, "", nil
	case SourceLocationSearch:
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		return targetURL + sep + "burpsy=" + url.QueryEscape(canary), "", nil
	case SourceReferrer:
		u, perr := url.Parse(targetURL)
		if perr != nil || u.Scheme == "" || u.Host == "" {
			return "", "", fmt.Errorf("domexec: cannot plant %s: target URL %q is not an absolute URL", source, targetURL)
		}
		ref := fmt.Sprintf("%s://%s/burpsy-referrer?%s", u.Scheme, u.Host, url.QueryEscape(canary))
		return targetURL, ref, nil
	case SourceWindowName, SourcePostMessage:
		return targetURL, "", nil
	default:
		return "", "", fmt.Errorf("domexec: cannot plant source %s: not a recognised source kind", source)
	}
}

// ObserveTaint loads targetURL with canary planted in source, then reports
// every dangerous sink the page's own script fed the canary to at runtime.
//
// SinkLocationAssign observations do not come from the injected script (see
// instrumentationJS's doc comment for why): they come from watching CDP
// frame-navigation events for a main-frame navigation, distinct from the one
// this call itself issues, whose destination URL contains the canary — i.e.
// proof the page's script redirected the browser using tainted data.
func (b *Browser) ObserveTaint(ctx context.Context, targetURL string, source SourceKind, canary string) ([]Observation, error) {
	if canary == "" {
		return nil, fmt.Errorf("domexec: canary must not be empty")
	}

	plantedURL, referrer, err := plantSource(targetURL, source, canary)
	if err != nil {
		return nil, err
	}

	tabCtx, cancel, err := b.newTab(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	var mu sync.Mutex
	var navigatedURLs []string
	chromedp.ListenTarget(tabCtx, func(ev any) {
		switch e := ev.(type) {
		case *page.EventFrameNavigated:
			if e.Frame != nil && e.Frame.ParentID == "" {
				mu.Lock()
				navigatedURLs = append(navigatedURLs, e.Frame.URL+e.Frame.URLFragment)
				mu.Unlock()
			}
		case *page.EventNavigatedWithinDocument:
			mu.Lock()
			navigatedURLs = append(navigatedURLs, e.URL)
			mu.Unlock()
		}
	})

	tasks := chromedp.Tasks{
		chromedp.ActionFunc(func(ctx context.Context) error {
			return page.Enable().Do(ctx)
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(instrumentationJS).Do(ctx)
			return err
		}),
	}

	if source == SourceWindowName {
		tasks = append(tasks,
			chromedp.Navigate("about:blank"),
			chromedp.Evaluate("window.name = "+jsString(canary)+";", nil),
		)
	}

	if referrer != "" {
		tasks = append(tasks, chromedp.ActionFunc(func(ctx context.Context) error {
			_, _, errText, _, navErr := page.Navigate(plantedURL).WithReferrer(referrer).Do(ctx)
			if navErr != nil {
				return navErr
			}
			if errText != "" {
				return fmt.Errorf("navigation to %q failed: %s", plantedURL, errText)
			}
			return nil
		}))
	} else {
		tasks = append(tasks, chromedp.Navigate(plantedURL))
	}

	tasks = append(tasks, chromedp.Sleep(400*time.Millisecond))

	if source == SourcePostMessage {
		tasks = append(tasks,
			chromedp.Evaluate("window.postMessage("+jsString(canary)+", '*');", nil),
			chromedp.Sleep(200*time.Millisecond),
		)
	}

	var raw string
	tasks = append(tasks, chromedp.Evaluate(`JSON.stringify(window.__burpsyTaint || [])`, &raw))

	if err := chromedp.Run(tabCtx, tasks...); err != nil {
		return nil, fmt.Errorf("domexec: observe taint at %q (source %s): %w", targetURL, source, err)
	}

	observations, err := decodeObservations(raw, source, []string{canary})
	if err != nil {
		return nil, err
	}

	mu.Lock()
	navigated := append([]string(nil), navigatedURLs...)
	mu.Unlock()
	return append(observations, navigationObservations(navigated, plantedURL, source, []string{canary})...), nil
}

// decodeObservations turns the JSON window.__burpsyTaint dump into observations, keeping only
// the sink calls whose argument carried one of tokens.
//
// tokens is a slice rather than a single canary because a stored load looks for every canary the
// scan has planted at once: one page render answers the whole ledger, and re-loading the page per
// token would multiply browser work by the ledger's size for no extra evidence.
func decodeObservations(raw string, source SourceKind, tokens []string) ([]Observation, error) {
	var records []taintRecord
	if err := json.Unmarshal([]byte(raw), &records); err != nil {
		return nil, fmt.Errorf("domexec: decode taint records: %w", err)
	}
	observations := make([]Observation, 0, len(records))
	for _, rec := range records {
		sink, ok := sinkTags[rec.Sink]
		if !ok {
			continue
		}
		for _, token := range tokens {
			if !strings.Contains(rec.Arg, token) {
				continue
			}
			observations = append(observations, Observation{
				Sink:       sink,
				Source:     source,
				Canary:     token,
				Argument:   rec.Arg,
				StackTrace: rec.Stack,
			})
			break
		}
	}
	return observations, nil
}

// navigationObservations reports a script-driven navigation carrying one of tokens as a
// SinkLocationAssign observation. loadedURL is the navigation this call issued itself, which is
// never a finding.
func navigationObservations(navigated []string, loadedURL string, source SourceKind, tokens []string) []Observation {
	var out []Observation
	for _, navURL := range navigated {
		// Our own navigation must not be reported as a flow. Comparing the raw strings is not
		// enough: CDP reports a normalised URL (Frame.URL carries an explicit "/" path where the
		// planted string may have none), so "http://host#c" and the reported "http://host/#c" are
		// the same navigation spelled two ways. An exact comparison therefore let every
		// hash-probed page report a DOM open redirection — the probe's own URL contains the canary
		// by construction. Canonicalise before comparing.
		if sameNavigation(navURL, loadedURL) || navURL == "about:blank" {
			continue
		}
		for _, token := range tokens {
			if !strings.Contains(navURL, token) {
				continue
			}
			out = append(out, Observation{
				Sink:     SinkLocationAssign,
				Source:   source,
				Canary:   token,
				Argument: navURL,
			})
			break
		}
	}
	return out
}

// sameNavigation reports whether two URL strings denote the same navigation, tolerating the
// normalisation CDP applies. An empty path and "/" are the same location, so they are
// folded before comparison; everything else (scheme, host, query, fragment) must match
// exactly, because a genuine script-driven redirect differs in at least one of those.
//
// Falls back to raw string equality when either side will not parse: an unparseable URL is
// not something to guess about, and treating it as "not our navigation" errs toward
// reporting rather than hiding.
func sameNavigation(a, b string) bool {
	if a == b {
		return true
	}
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	canonPath := func(p string) string {
		if p == "" {
			return "/"
		}
		return p
	}
	return ua.Scheme == ub.Scheme &&
		ua.Host == ub.Host &&
		canonPath(ua.Path) == canonPath(ub.Path) &&
		ua.RawQuery == ub.RawQuery &&
		ua.Fragment == ub.Fragment
}

// RenderedDOM returns targetURL's document.documentElement.outerHTML after
// script execution, through the same instrumented pipeline ObserveTaint
// uses. Instrumenting here too, rather than navigating plain, is what makes
// this the harness's proof that the sink wrappers call through correctly:
// a page whose only visible content comes from a wrapped sink (e.g.
// document.write) must still show that content here, or the wrappers would
// be silently breaking every page they touch.
//
// This is also the other half the DOM catalog rows need: some are about
// content that exists only once the page's own script has run (e.g. a
// client-side template rendering stored data), which is invisible to an
// HTTP-only scanner that only ever sees the raw response body.
func (b *Browser) RenderedDOM(ctx context.Context, targetURL string) (string, error) {
	tabCtx, cancel, err := b.newTab(ctx)
	if err != nil {
		return "", err
	}
	defer cancel()

	var html string
	err = chromedp.Run(tabCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(instrumentationJS).Do(ctx)
			return err
		}),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(300*time.Millisecond),
		chromedp.Evaluate(`document.documentElement.outerHTML`, &html),
	)
	if err != nil {
		return "", fmt.Errorf("domexec: render %q: %w", targetURL, err)
	}
	return html, nil
}

// StoredRender is one load of a page that was given no attacker-controlled source at all.
//
// Both halves are returned from a single load on purpose. HTML alone says the value came back;
// Observations say a script carried it into a dangerous sink. A caller given only the first would
// have to report every page that merely displays stored data, which is what "(stored DOM-based)"
// is not about.
type StoredRender struct {
	// HTML is the document after script has run.
	HTML string
	// Observations are the sink calls whose argument carried one of the tokens asked about.
	Observations []Observation
}

// ObserveStored loads targetURL with nothing planted and reports what the page's own script did
// with values already stored in the application.
//
// This is the browser half of the stored lifecycle. A canary planted over HTTP can reach the page
// through an API call the raw response body never contains, so an HTTP-only second look reports
// such a page as clean when it is the only place the value is ever rendered. Loading it here is the
// only way that flow is visible at all.
//
// An empty token set is an error rather than an empty result: it means the caller is asking which
// canaries surfaced without naming any, and answering "none" would read as a clean page.
func (b *Browser) ObserveStored(ctx context.Context, targetURL string, tokens []string) (StoredRender, error) {
	var out StoredRender
	if len(tokens) == 0 {
		return out, fmt.Errorf("domexec: observe stored at %q: no tokens to look for", targetURL)
	}

	tabCtx, cancel, err := b.newTab(ctx)
	if err != nil {
		return out, err
	}
	defer cancel()

	var mu sync.Mutex
	var navigatedURLs []string
	chromedp.ListenTarget(tabCtx, func(ev any) {
		switch e := ev.(type) {
		case *page.EventFrameNavigated:
			if e.Frame != nil && e.Frame.ParentID == "" {
				mu.Lock()
				navigatedURLs = append(navigatedURLs, e.Frame.URL+e.Frame.URLFragment)
				mu.Unlock()
			}
		case *page.EventNavigatedWithinDocument:
			mu.Lock()
			navigatedURLs = append(navigatedURLs, e.URL)
			mu.Unlock()
		}
	})

	var raw string
	err = chromedp.Run(tabCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return page.Enable().Do(ctx)
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(instrumentationJS).Do(ctx)
			return err
		}),
		chromedp.Navigate(targetURL),
		// Longer than RenderedDOM's wait: a stored DOM flow characteristically fetches the value
		// over the network first, so the sink call happens a round trip after load rather than
		// inline in the parsed script.
		chromedp.Sleep(700*time.Millisecond),
		chromedp.Evaluate(`JSON.stringify(window.__burpsyTaint || [])`, &raw),
		chromedp.Evaluate(`document.documentElement.outerHTML`, &out.HTML),
	)
	if err != nil {
		return out, fmt.Errorf("domexec: observe stored at %q: %w", targetURL, err)
	}

	obs, err := decodeObservations(raw, SourceStored, tokens)
	if err != nil {
		return out, err
	}
	mu.Lock()
	navigated := append([]string(nil), navigatedURLs...)
	mu.Unlock()
	out.Observations = append(obs, navigationObservations(navigated, targetURL, SourceStored, tokens)...)
	return out, nil
}

// ObservationsForSink filters obs down to those matching sink.
func ObservationsForSink(obs []Observation, sink SinkKind) []Observation {
	var out []Observation
	for _, o := range obs {
		if o.Sink == sink {
			out = append(out, o)
		}
	}
	return out
}
