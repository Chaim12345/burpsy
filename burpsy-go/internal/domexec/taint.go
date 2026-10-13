package domexec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
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

	nav := &navigationRecorder{}
	chromedp.ListenTarget(tabCtx, nav.listen)

	// window.name cannot be planted by navigating first: planting relied on the
	// browser preserving window.name across a navigation, and obscura rebuilds
	// its window object per document, dropping it — which turned every
	// reflected-DOM row dark (11 catalog rows demonstrated by Chrome but missed
	// here). Injecting the canary at the end of the preload script runs before
	// the page's own scripts on every engine, relies on no cross-navigation
	// persistence, and is observationally identical to arriving with an
	// attacker-set window.name.
	preload := instrumentationJS
	if source == SourceWindowName {
		preload += "\nwindow.name = " + jsString(canary) + ";"
	}

	tasks := chromedp.Tasks{
		chromedp.ActionFunc(func(ctx context.Context) error {
			return page.Enable().Do(ctx)
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(preload).Do(ctx)
			return err
		}),
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

	return append(observations, navigationObservations(nav.later(), plantedURL, source, []string{canary})...), nil
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
			if engineInternalStack(rec.Stack) {
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

// engineInternalStack reports whether the sink call at the top of this stack was made by the
// engine's own bootstrap machinery rather than by the page under test.
//
// Obscura implements location/URL handling in a JS bootstrap layer that itself calls instrumented
// platform functions — reading location.search routes through JSON.parse on the page's URL. Those
// calls carry attacker-controlled canaries (they ride in the URL by construction), so without this
// filter every URL-bearing navigation reported a Client-side JSON injection on provably safe
// endpoints. Chrome has no such layer and is unaffected.
//
// The discriminator is structural, not textual guesswork: every observation's stack begins with
// exactly two <preload> frames (record + the wrapper), so the first frame after them is whoever
// actually made the call. A page frame ("at http://…") means the page did it — keep. An
// "<obscura:" frame means the engine did it internally — drop. Deeper bootstrap frames below a
// page frame are ordinary: a page may legitimately read location.search (engine shim) and then
// parse the value itself, and that flow must survive.
func engineInternalStack(stack string) bool {
	const marker = "<obscura:"
	for _, line := range strings.Split(stack, "\n") {
		frame := strings.TrimSpace(line)
		if !strings.HasPrefix(frame, "at ") {
			continue
		}
		if strings.Contains(frame, "<preload>") {
			// record() and the wrapper itself.
			continue
		}
		// The first frame outside the preload harness is whoever made the call;
		// everything deeper is irrelevant to attribution.
		return strings.Contains(frame, marker)
	}
	return false
}

// navigationRecorder collects the main-frame navigations of one tab, setting aside the commit of
// the navigation the caller issued itself.
//
// # Why the first commit is never a flow
//
// The navigation the caller issues commits exactly once, at whatever URL the server finally
// answered from: an HTTP 3xx is followed inside that one navigation, and Chrome carries the
// fragment of the requested URL onto a Location that has none (the Fetch/HTML redirect rule). So a
// hash-planted load of an endpoint that answers "302 Location: /" commits at "/#canary". Compared
// only against the URL that was planted, that commit looked like a navigation to a new place
// carrying the canary - and every redirecting endpoint was reported as DOM-based open
// redirection, the safe ones included, with no script involved at all (the server never even sees
// a fragment). A script-driven navigation needs a document whose script ran, so it can only come
// after that first commit; the first commit is the caller's own navigation, wherever the server
// sent it.
//
// Same-document navigations (pushState, fragment changes) are always recorded: none is the
// caller's own load.
type navigationRecorder struct {
	mu        sync.Mutex
	committed bool
	urls      []string
}

func (r *navigationRecorder) listen(ev any) {
	switch e := ev.(type) {
	case *page.EventFrameNavigated:
		if e.Frame == nil || e.Frame.ParentID != "" {
			return
		}
		u := e.Frame.URL + e.Frame.URLFragment
		r.mu.Lock()
		defer r.mu.Unlock()
		if u == "about:blank" && !r.committed {
			// The new tab's own blank document, before the caller's navigation.
			return
		}
		if !r.committed {
			r.committed = true
			return
		}
		r.urls = append(r.urls, u)
	case *page.EventNavigatedWithinDocument:
		r.mu.Lock()
		r.urls = append(r.urls, e.URL)
		r.mu.Unlock()
	}
}

// later returns the navigations recorded after the caller's own commit.
func (r *navigationRecorder) later() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.urls...)
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
// RenderOptions is what a render waits for before it reads the DOM, and what it gives up on.
//
// The three are separate because they fail differently and an operator diagnosing a thin crawl needs
// to know which one bit. Burp exposes the same pair ("Network idle threshold (ms):",
// map_root.tsv:7393, and the DOM-quiet window at Zgjj.java:161-165), and the reason it matters is
// that a modern target's content arrives AFTER load: a render that reads at the load event sees an
// empty shell, contributes no links, and the crawl then reports an application as having almost no
// locations — a confident wrong answer (burpsy-react-ui-efra).
type RenderOptions struct {
	// DOMQuiet is how long the DOM must be UNCHANGED before the page counts as settled. Zero takes
	// DefaultDOMQuiet.
	//
	// A page that fetches and renders in three steps is empty at the load event and complete a
	// moment later; this is the window that catches it.
	DOMQuiet time.Duration
	// NetworkIdle is how long no request may be in flight before the page counts as settled. Zero
	// takes DefaultNetworkIdle.
	//
	// Separate from DOMQuiet because a page can be quiet in the DOM while a request is still running
	// (a skeleton that has not been replaced yet), and can be busy in the DOM with no request at all
	// (a carousel). Whichever fires first settles it; requiring both would hang on a page that
	// polls forever, which is a normal thing for a dashboard to do.
	NetworkIdle time.Duration
	// MaxWait is the hard cap. Zero takes DefaultMaxRenderWait.
	//
	// It exists because both windows above are LOWER bounds on quietness, and a page that never goes
	// quiet — a websocket, a polling feed, an analytics beacon that never stops — would otherwise
	// wait forever. Capping and REPORTING the cap is the difference between a truncated render and a
	// hung crawl.
	MaxWait time.Duration
	// Screenshot asks for a JPEG of the page as it was when the DOM was read (burpsy-react-ui-1l3x,
	// the live crawl view). Off by default: a capture costs a round trip and an encode, and only a
	// caller watching the crawl wants one — that caller throttles how often it asks.
	Screenshot bool
}

// The defaults, and the reason they are non-zero: the floor of this feature is the 300 ms the
// previous implementation slept unconditionally, so a crawl configured with nothing waits at least
// as long as it always did and no crawl gets SLOWER. Zero would mean "read at the load event",
// which is the defect.
const (
	// DefaultDOMQuiet is the settle window for the DOM. 300 ms is the fixed sleep the
	// implementation this replaces used unconditionally, so it is the FLOOR: a page that settles early
	// returns as soon as it does, and 300 ms only applies to one that keeps changing.
	DefaultDOMQuiet = 300 * time.Millisecond
	// DefaultNetworkIdle is the settle window for in-flight requests. Shorter than DOMQuiet because a
	// pending request is a stronger signal that something is coming than a DOM that has not changed
	// yet.
	DefaultNetworkIdle = 500 * time.Millisecond
	// DefaultMaxRenderWait caps the whole wait. Ten seconds is longer than any first paint an
	// operator will sit through and short enough that a crawl of a thousand pages does not spend
	// three hours on the ones that never settle.
	DefaultMaxRenderWait = 10 * time.Second
)

func (o RenderOptions) withDefaults() RenderOptions {
	if o.DOMQuiet <= 0 {
		o.DOMQuiet = DefaultDOMQuiet
	}
	if o.NetworkIdle <= 0 {
		o.NetworkIdle = DefaultNetworkIdle
	}
	if o.MaxWait <= 0 {
		o.MaxWait = DefaultMaxRenderWait
	}
	return o
}

// RenderOutcome says how a render ended, so a caller can report a truncated page rather than
// presenting it as an empty one.
type RenderOutcome struct {
	// Settled reports that the page went quiet inside MaxWait.
	Settled bool
	// Capped reports that MaxWait was reached first — the DOM was read while the page was still
	// changing, so whatever it did not have yet is missing rather than absent.
	Capped bool
	// Waited is how long the render actually took.
	Waited time.Duration
	// Requests are the XHR and fetch requests the page itself issued while it rendered
	// (burpsy-react-ui-hzzl): the run-time API calls a single-page app makes, which appear in no
	// served byte and no rendered link. Capped at MaxRenderedRequests; RequestsDropped counts the rest.
	Requests        []RenderedRequest
	RequestsDropped int
	// Screenshot is the JPEG RenderOptions.Screenshot asked for; nil when not asked, or when the
	// capture failed (a render that succeeded is not failed for want of a picture).
	Screenshot []byte
}

// RenderedRequest is one request a page issued at run time.
type RenderedRequest struct {
	URL    string
	Method string
	// Type is the CDP resource type, "XHR" or "Fetch".
	Type string
}

// MaxRenderedRequests bounds how many run-time requests one render records, so a page that polls or
// streams cannot grow a crawl's frontier without bound.
const MaxRenderedRequests = 200

// RenderedDOMWithOptions reads the rendered DOM of one page, waiting for it to settle first, and
// says whether it did.
func (b *Browser) RenderedDOMWithOptions(ctx context.Context, targetURL string, opts RenderOptions) (string, RenderOutcome, error) {
	opts = opts.withDefaults()
	started := time.Now()
	var shot []byte
	html, reqs, dropped, err := b.renderedDOMIn(ctx, b.newTab, targetURL, opts, &shot)
	outcome := RenderOutcome{Waited: time.Since(started), Requests: reqs, RequestsDropped: dropped, Screenshot: shot}
	if err != nil {
		return "", outcome, err
	}
	// A render that finished inside the cap with the page quiet is settled. We do not measure
	// "quiet" again here: the wait below already established it, and re-measuring would cost another
	// window for an answer the caller does not use.
	outcome.Settled = outcome.Waited < opts.MaxWait
	outcome.Capped = !outcome.Settled
	return html, outcome, nil
}

func (b *Browser) RenderedDOM(ctx context.Context, targetURL string) (string, error) {
	html, _, err := b.RenderedDOMWithOptions(ctx, targetURL, RenderOptions{})
	return html, err
}

// renderedDOMIn renders in a tab newTab opens: the Browser's default context for an ordinary render,
// or an isolated Session's for an authenticated one (Session.RenderedDOMWithOptions).
func (b *Browser) renderedDOMIn(ctx context.Context, newTab func(context.Context) (context.Context, context.CancelFunc, error), targetURL string, opts RenderOptions, shot *[]byte) (string, []RenderedRequest, int, error) {
	tabCtx, cancel, err := newTab(ctx)
	if err != nil {
		return "", nil, 0, err
	}
	defer cancel()

	// The page's own run-time requests, recorded as the browser announces them. XHR and Fetch only:
	// documents, scripts and images are already reachable from the served or rendered markup, and the
	// requests a page MAKES are the ones nothing else can see.
	var mu sync.Mutex
	var reqs []RenderedRequest
	dropped := 0
	chromedp.ListenTarget(tabCtx, func(ev any) {
		e, ok := ev.(*network.EventRequestWillBeSent)
		if !ok || e.Request == nil || (e.Type != network.ResourceTypeXHR && e.Type != network.ResourceTypeFetch) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if len(reqs) >= MaxRenderedRequests {
			dropped++
			return
		}
		reqs = append(reqs, RenderedRequest{URL: e.Request.URL, Method: e.Request.Method, Type: string(e.Type)})
	})

	var html string
	err = chromedp.Run(tabCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return network.Enable().Do(ctx)
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(instrumentationJS).Do(ctx)
			return err
		}),
		chromedp.Navigate(targetURL),
		// A plain action, not a chromedp one: the wait reads the DOM on every tick with its own
		// Evaluate, so wrapping it would nest an action inside an action and lose the tab context.
		chromedp.ActionFunc(func(ctx context.Context) error {
			waitForSettle(ctx, opts)
			return nil
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			if !opts.Screenshot || shot == nil {
				return nil
			}
			// Viewport only, JPEG at 50: a live view is a glance at what the crawler is on, and a
			// full-page PNG of a long page is megabytes per frame.
			*shot = captureFrame(ctx)
			return nil
		}),
		chromedp.Evaluate(`document.documentElement.outerHTML`, &html),
	)
	mu.Lock()
	out, gone := append([]RenderedRequest(nil), reqs...), dropped
	mu.Unlock()
	if err != nil {
		return "", out, gone, fmt.Errorf("domexec: render %q: %w", targetURL, err)
	}
	return html, out, gone, nil
}

// captureFrame takes a viewport JPEG of the tab, or returns nil.
//
// Bounded by its own short deadline, because a capture is a nice-to-have riding on a render that is
// not: measured against this build's Chromium (147, headless), Page.captureScreenshot in a tab that is
// not the browser's front tab waits for a compositor frame that never comes, and without a bound it
// held the render until the whole tab timed out — 30 s per page, and the render then failed. The
// tab is brought to the front first, which is what makes the frame arrive; the bound is what keeps a
// capture that still does not from costing the render anything but itself.
func captureFrame(ctx context.Context) []byte {
	capCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_ = page.BringToFront().Do(capCtx)
	buf, err := page.CaptureScreenshot().WithFormat(page.CaptureScreenshotFormatJpeg).WithQuality(50).Do(capCtx)
	if err != nil {
		return nil
	}
	return buf
}

// waitForSettle blocks until the page is quiet in either the DOM or the network, or MaxWait elapses.
//
// Both signals are polled rather than waited on, because neither is an event chromedp can await
// directly: the DOM has no "changed" event, and a request counter has to be read out of the page on
// every tick. The poll is deliberately coarse — the window is measured in hundreds of milliseconds,
// so a 50 ms tick costs nothing measurable and a finer one would only burn the render's own budget.
//
// The cap is enforced by the SAME deadline rather than by a second timer, so a page that never settles
// costs exactly MaxWait and not MaxWait plus a timeout race.
func waitForSettle(ctx context.Context, opts RenderOptions) {
	deadline := time.Now().Add(opts.MaxWait)
	// lastHTML is the previous sample, and lastChange is when it last differed. A page that is still
	// being written keeps pushing lastChange forward and never looks quiet, which is the behaviour the
	// DOM window is asking for.
	lastHTML, lastChange := "", time.Now()
	for {
		if time.Now().After(deadline) {
			return
		}
		var now string
		if err := chromedp.Evaluate(`document.documentElement.outerHTML`, &now).Do(ctx); err != nil {
			// The page is gone or the tab died: there is nothing left to wait for, and the caller
			// reports the render as unavailable rather than as an empty page.
			return
		}
		if now != lastHTML {
			lastHTML, lastChange = now, time.Now()
		}
		if time.Since(lastChange) >= opts.DOMQuiet {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
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

	nav := &navigationRecorder{}
	chromedp.ListenTarget(tabCtx, nav.listen)

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
	out.Observations = append(obs, navigationObservations(nav.later(), targetURL, SourceStored, tokens)...)
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
