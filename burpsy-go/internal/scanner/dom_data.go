// The source, sink, sanitizer and weak-encoder tables the static DOM pass in dom.go runs on.
//
// # Why the sets are data in one file, not literals in the engine
//
// A taint analysis is only as auditable as its source and sink lists. Scattered string literals
// inside matching code cannot be reviewed by anyone who is not also reading the matcher, and cannot
// be extended without touching the matcher. Everything the engine recognises is therefore declared
// here, as tables, with the catalogued issue each sink maps to written on the same line — so
// "which issues can this pass ever raise, and off which sink" is answered by reading one file.
//
// # Why sinks name a catalogued issue rather than a made-up one
//
// Every Issue value below is the *base* of a name that exists in Burp's shipped catalog
// (catalog_data.go), minus the parenthesised variant. domIssueName joins the base to the variant
// the source kind implies, and dom.go then looks the joined name up with ByName and fails loudly if
// it is absent — see TestEverySinkNamesACatalogedIssue. A sink whose issue name does not resolve is
// a bug in this table, not a new issue type: this pass never invents issue vocabulary, and never
// writes its own remediation.
package scanner

import (
	"sort"
	"strings"
)

// DOMSourceKind is where an attacker gets their data in, which decides which catalogued *variant*
// of an issue name a flow off that source is reported under.
//
// Burp's catalog carries three variants of most DOM issue: "(DOM-based)", "(reflected DOM-based)"
// and "(stored DOM-based)". This pass reports the first two kinds below and never the reflected
// variant, because "reflected" means the tainted value came back from the server in this response,
// and establishing that requires correlating the value against the request — which a pass that only
// reads the response body cannot do. That is a named omission, not an oversight: the reflected
// variants are simply outside what a response-only static pass can honestly claim.
type DOMSourceKind int

const (
	// DOMSourceURL is data the attacker controls by handing the victim a crafted URL — the
	// classic DOM-based case, and the one the "(DOM-based)" variant names.
	DOMSourceURL DOMSourceKind = iota
	// DOMSourceStored is data read back out of client-side storage, which an earlier request may
	// have planted. Reported under the "(stored DOM-based)" variant.
	DOMSourceStored
	// DOMSourceMessage is data arriving from another document (postMessage). Reported under
	// "(DOM-based)": the catalog has no separate variant for cross-document delivery.
	DOMSourceMessage
)

// variant is the parenthesised suffix of the catalogued issue name for this source kind.
func (k DOMSourceKind) variant() string {
	switch k {
	case DOMSourceStored:
		return "(stored DOM-based)"
	case DOMSourceURL, DOMSourceMessage:
		return "(DOM-based)"
	}
	return "(DOM-based)"
}

func (k DOMSourceKind) String() string {
	switch k {
	case DOMSourceURL:
		return "URL-controlled"
	case DOMSourceStored:
		return "client-side storage"
	case DOMSourceMessage:
		return "cross-document message"
	}
	return "unknown source kind"
}

// DOMSource is one recognised taint source.
type DOMSource struct {
	// Expr is the JavaScript expression text matched in the script, verbatim.
	Expr string
	// Kind decides the catalogued variant a flow off this source is reported under.
	Kind DOMSourceKind
}

// domSources is every taint source this pass recognises.
//
// Held sorted longest-Expr-first by init, so `location.hash` is matched in preference to the bare
// `location` that is a prefix of it. Without that ordering the coarser entry would win and every
// flow would be attributed to the wrong expression.
var domSources = []DOMSource{
	{Expr: "location.hash", Kind: DOMSourceURL},
	{Expr: "location.search", Kind: DOMSourceURL},
	{Expr: "location.href", Kind: DOMSourceURL},
	{Expr: "location.pathname", Kind: DOMSourceURL},
	{Expr: "location.hostname", Kind: DOMSourceURL},
	{Expr: "location.host", Kind: DOMSourceURL},
	{Expr: "location.protocol", Kind: DOMSourceURL},
	{Expr: "document.location", Kind: DOMSourceURL},
	{Expr: "window.location", Kind: DOMSourceURL},
	{Expr: "location", Kind: DOMSourceURL},
	{Expr: "document.URL", Kind: DOMSourceURL},
	{Expr: "document.documentURI", Kind: DOMSourceURL},
	{Expr: "document.baseURI", Kind: DOMSourceURL},
	{Expr: "document.referrer", Kind: DOMSourceURL},
	{Expr: "window.name", Kind: DOMSourceURL},
	{Expr: "history.state", Kind: DOMSourceURL},

	{Expr: "localStorage.getItem", Kind: DOMSourceStored},
	{Expr: "sessionStorage.getItem", Kind: DOMSourceStored},
	{Expr: "document.cookie", Kind: DOMSourceStored},

	// Only the conventional parameter name is recognised. A `message` handler that names its
	// event parameter anything else — `function(e){ ... e.data ... }` is at least as common — is
	// missed, and matching a bare `.data` instead would collide with jQuery's `event.data` and
	// with any application object that happens to have a `data` property. Named limit, not a gap
	// waiting to be closed by loosening the match.
	{Expr: "event.data", Kind: DOMSourceMessage},
}

// DOMSinkForm is how a sink consumes its tainted value, which decides how dom.go looks for it.
type DOMSinkForm int

const (
	// DOMSinkAssign is a property written to: `el.innerHTML = tainted`.
	DOMSinkAssign DOMSinkForm = iota
	// DOMSinkCall is a function the value is passed to: `eval(tainted)`.
	DOMSinkCall
	// DOMSinkCallString is a function that is only a sink when handed a *string*:
	// `setTimeout(tainted, 0)` executes it, `setTimeout(function(){}, 0)` does not. Passing a
	// function literal is the overwhelmingly common, entirely safe use, so treating this as a
	// plain DOMSinkCall would make the pass useless noise on ordinary code.
	DOMSinkCallString
)

// DOMSink is one recognised sink.
type DOMSink struct {
	// Match is the property name (DOMSinkAssign) or callee text (DOMSinkCall*) matched in the
	// script, verbatim.
	Match string
	Form  DOMSinkForm
	// Issue is the catalogued issue name with its variant suffix removed; domIssueName rejoins it.
	Issue string
}

// Catalogued issue-name bases. Named constants rather than repeated string literals so a typo is a
// compile error in one place instead of a silently unresolvable catalog lookup in several.
const (
	domIssueXSS         = "Cross-site scripting"
	domIssueJSInjection = "JavaScript injection"
	domIssueOpenRedir   = "Open redirection"
	domIssueDocDomain   = "Document domain manipulation"
	domIssueCookie      = "Cookie manipulation"
	domIssueStorage     = "HTML5 storage manipulation"
	domIssueWebMessage  = "HTML5 web message manipulation"
	domIssueWebSocket   = "WebSocket URL poisoning"
	domIssueLink        = "Link manipulation"
	domIssueClientSQL   = "Client-side SQL injection"
	domIssueXPath       = "Client-side XPath injection"
	domIssueClientJSON  = "Client-side JSON injection"
	domIssueLocalFile   = "Local file path manipulation"
)

// domSinks is every sink this pass recognises, sorted longest-Match-first by init for the same
// prefix reason as domSources: `location.href` must beat the bare `href` that would otherwise
// mis-attribute a navigation assignment to link manipulation.
//
// # What is deliberately absent
//
//   - "Denial of service (DOM-based)" — Burp raises it off constructs (a tainted RegExp, a tainted
//     loop bound) whose danger is a property of the *value*, not of the callee, and a lexical pass
//     cannot judge that. Reporting it off a callee name would be a guess wearing a catalog name.
//   - "DOM data manipulation (DOM-based)" — its sinks are exactly the safe sinks in
//     domSafeSinks below (textContent and friends). It is catalogued at info severity and firing
//     on every text write would bury the actionable findings; suppression is recorded rather than
//     silent, see DOMSuppressReasonSafeSink.
//   - `location.pathname` / `.search` / `.hash` *assignment*. These navigate within the current
//     origin, so calling them open redirection would overstate what an attacker gains.
//   - `Element.append`/`prepend`/`after`/`before`. jQuery's parse HTML and are sinks; the native
//     DOM methods of the same names insert text and are not. The two are indistinguishable
//     lexically, and guessing either way is worse than declining.
var domSinks = []DOMSink{
	{Match: "innerHTML", Form: DOMSinkAssign, Issue: domIssueXSS},
	{Match: "outerHTML", Form: DOMSinkAssign, Issue: domIssueXSS},
	{Match: "srcdoc", Form: DOMSinkAssign, Issue: domIssueXSS},
	{Match: "document.domain", Form: DOMSinkAssign, Issue: domIssueDocDomain},
	{Match: "document.cookie", Form: DOMSinkAssign, Issue: domIssueCookie},
	{Match: "location.href", Form: DOMSinkAssign, Issue: domIssueOpenRedir},
	{Match: "location.protocol", Form: DOMSinkAssign, Issue: domIssueOpenRedir},
	{Match: "location.hostname", Form: DOMSinkAssign, Issue: domIssueOpenRedir},
	{Match: "location.host", Form: DOMSinkAssign, Issue: domIssueOpenRedir},
	{Match: "window.location", Form: DOMSinkAssign, Issue: domIssueOpenRedir},
	{Match: "document.location", Form: DOMSinkAssign, Issue: domIssueOpenRedir},
	{Match: "location", Form: DOMSinkAssign, Issue: domIssueOpenRedir},
	{Match: "href", Form: DOMSinkAssign, Issue: domIssueLink},
	{Match: "action", Form: DOMSinkAssign, Issue: domIssueLink},
	{Match: "src", Form: DOMSinkAssign, Issue: domIssueLink},

	{Match: "eval", Form: DOMSinkCall, Issue: domIssueJSInjection},
	{Match: "Function", Form: DOMSinkCall, Issue: domIssueJSInjection},
	{Match: "execScript", Form: DOMSinkCall, Issue: domIssueJSInjection},
	{Match: "setTimeout", Form: DOMSinkCallString, Issue: domIssueJSInjection},
	{Match: "setInterval", Form: DOMSinkCallString, Issue: domIssueJSInjection},
	{Match: "setImmediate", Form: DOMSinkCallString, Issue: domIssueJSInjection},
	{Match: "document.write", Form: DOMSinkCall, Issue: domIssueXSS},
	{Match: "document.writeln", Form: DOMSinkCall, Issue: domIssueXSS},
	{Match: ".insertAdjacentHTML", Form: DOMSinkCall, Issue: domIssueXSS},
	{Match: ".html", Form: DOMSinkCall, Issue: domIssueXSS},
	{Match: "location.assign", Form: DOMSinkCall, Issue: domIssueOpenRedir},
	{Match: "location.replace", Form: DOMSinkCall, Issue: domIssueOpenRedir},
	{Match: "window.open", Form: DOMSinkCall, Issue: domIssueOpenRedir},
	{Match: ".postMessage", Form: DOMSinkCall, Issue: domIssueWebMessage},
	{Match: "WebSocket", Form: DOMSinkCall, Issue: domIssueWebSocket},
	{Match: "localStorage.setItem", Form: DOMSinkCall, Issue: domIssueStorage},
	{Match: "sessionStorage.setItem", Form: DOMSinkCall, Issue: domIssueStorage},
	{Match: ".executeSql", Form: DOMSinkCall, Issue: domIssueClientSQL},
	{Match: "document.evaluate", Form: DOMSinkCall, Issue: domIssueXPath},
	{Match: ".selectNodes", Form: DOMSinkCall, Issue: domIssueXPath},
	{Match: "JSON.parse", Form: DOMSinkCall, Issue: domIssueClientJSON},
	{Match: "history.pushState", Form: DOMSinkCall, Issue: domIssueLink},
	{Match: "history.replaceState", Form: DOMSinkCall, Issue: domIssueLink},
	{Match: "requestFileSystem", Form: DOMSinkCall, Issue: domIssueLocalFile},
	{Match: "resolveLocalFileSystemURL", Form: DOMSinkCall, Issue: domIssueLocalFile},
}

// domSafeSinks are assignment targets that cannot execute or navigate whatever is written to them.
//
// A tainted value reaching one of these is a real dataflow and Burp would catalogue it as info-level
// "DOM data manipulation", but it is not an execution or navigation primitive. The flow is
// therefore suppressed *and recorded* (DOMSuppressReasonSafeSink) rather than dropped, so a caller
// can still see that the pass traced it and decided.
var domSafeSinks = []string{
	"textContent",
	"innerText",
	"nodeValue",
}

// DOMSanitizer is an operation this pass accepts as a defence, and the issues it is accepted for.
type DOMSanitizer struct {
	// Call is the callee text matched in the script, verbatim.
	Call string
	// Neutralises lists the catalogued issue *bases* this operation is accepted as a defence for.
	// Empty means it is accepted for every issue this pass can report.
	//
	// This column is the difference between an honest sanitizer list and a wishful one. HTML
	// escaping genuinely stops a value becoming markup and genuinely does nothing about a
	// `javascript:` URL reaching a navigation sink; collapsing both into "sanitized" would
	// suppress a live open redirection on the strength of a defence aimed at a different bug.
	Neutralises []string
	// Why is the one line a report shows next to a suppression, so the judgement is inspectable
	// rather than implied by the operation's name.
	Why string
}

// covers reports whether this sanitizer is accepted for the given catalogued issue base.
func (s DOMSanitizer) covers(issueBase string) bool {
	if len(s.Neutralises) == 0 {
		return true
	}
	for _, n := range s.Neutralises {
		if n == issueBase {
			return true
		}
	}
	return false
}

// domSanitizers is every operation this pass accepts as a defence.
//
// # The accepted heuristic, and its residual hole
//
// encodeURIComponent is accepted for every issue, which is a deliberate simplification with one
// known hole: it does not escape the apostrophe, so a value concatenated into a single-quoted
// attribute inside an innerHTML string can still break out of that attribute. Accepting it anyway
// matches how the defence is understood in practice and keeps the pass from drowning ordinary
// correct code in caveats — but the hole is real, and a flow suppressed on this basis is recorded
// in DOMAnalysis.Suppressed with this Why text attached, not silently deleted.
var domSanitizers = []DOMSanitizer{
	{
		Call: "encodeURIComponent",
		Why:  "percent-encodes the reserved and markup-significant characters; accepted for every sink this pass reports, with the documented apostrophe caveat",
	},
	{
		Call: "parseInt",
		Why:  "coerces to a number, so no attacker-chosen character survives",
	},
	{
		Call: "parseFloat",
		Why:  "coerces to a number, so no attacker-chosen character survives",
	},
	{
		Call: "Number",
		Why:  "coerces to a number, so no attacker-chosen character survives",
	},
	{
		Call:        "DOMPurify.sanitize",
		Neutralises: []string{domIssueXSS, domIssueJSInjection},
		Why:         "an HTML sanitizer: accepted for markup and script-execution sinks, not for navigation or storage sinks where its output is not markup at all",
	},
	{
		Call:        "sanitizeHtml",
		Neutralises: []string{domIssueXSS, domIssueJSInjection},
		Why:         "an HTML sanitizer: accepted for markup and script-execution sinks only",
	},
	{
		Call:        "escapeHtml",
		Neutralises: []string{domIssueXSS},
		Why:         "HTML-escapes the value, which stops it becoming markup and does nothing about a javascript: URL reaching a navigation sink",
	},
	{
		Call:        "escapeHTML",
		Neutralises: []string{domIssueXSS},
		Why:         "HTML-escapes the value, which stops it becoming markup and does nothing about a javascript: URL reaching a navigation sink",
	},
	{
		Call:        "htmlEscape",
		Neutralises: []string{domIssueXSS},
		Why:         "HTML-escapes the value, which stops it becoming markup and does nothing about a javascript: URL reaching a navigation sink",
	},
	{
		Call:        "Handlebars.escapeExpression",
		Neutralises: []string{domIssueXSS},
		Why:         "HTML-escapes the value, which stops it becoming markup and does nothing about a javascript: URL reaching a navigation sink",
	},
}

// DOMWeakEncoder is an operation that looks like a defence and is not accepted as one.
//
// Recognising these by name is worth more than ignoring them. A flow through one is still reported
// as a finding — failing towards reporting, because the likely reading of `escape(location.hash)`
// reaching document.write is a developer who believed they were safe — but the finding's evidence
// names the operation and says why it was not accepted, so the judgement travels with the finding
// instead of the operator having to guess why the scanner disagreed with the code's apparent intent.
type DOMWeakEncoder struct {
	Call string
	Why  string
}

var domWeakEncoders = []DOMWeakEncoder{
	{
		Call: "encodeURI",
		Why:  "encodeURI leaves #, ?, &, /, :, ;, =, + and , intact, so it does not stop a javascript: scheme or a host swap reaching a navigation sink",
	},
	{
		Call: "escape",
		Why:  "escape() is a legacy, non-Unicode-safe encoder that was never an HTML or URL defence; it leaves the apostrophe and the plus sign intact",
	},
	{
		Call: ".replace",
		Why:  "a hand-rolled .replace() filter: this pass cannot evaluate which characters it removes, or whether it removes them more than once",
	},
}

// domIssueName joins a sink's catalogued issue base to the variant the source kind implies. The
// result is looked up in the shipped catalog by the caller; nothing here assumes it resolves.
func domIssueName(issueBase string, kind DOMSourceKind) string {
	return issueBase + " " + kind.variant()
}

// init sorts both matched tables longest-match-first. Doing it here rather than hand-maintaining
// the order means adding a table row cannot silently break prefix precedence for an existing one.
func init() {
	sort.SliceStable(domSources, func(i, j int) bool {
		return len(domSources[i].Expr) > len(domSources[j].Expr)
	})
	sort.SliceStable(domSinks, func(i, j int) bool {
		return len(domSinks[i].Match) > len(domSinks[j].Match)
	})
	sort.SliceStable(domSanitizers, func(i, j int) bool {
		return len(domSanitizers[i].Call) > len(domSanitizers[j].Call)
	})
	sort.SliceStable(domWeakEncoders, func(i, j int) bool {
		return len(domWeakEncoders[i].Call) > len(domWeakEncoders[j].Call)
	})
}

// domIdentByte reports whether b can appear inside a JavaScript identifier. Used by the token
// matcher to refuse a match that is really the middle of a longer name.
func domIdentByte(b byte) bool {
	return b == '_' || b == '$' ||
		(b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z')
}

// domContainsToken reports whether needle appears in hay as a whole member-path token rather than
// as a fragment of a longer identifier — so `locationCount` does not match `location`, and
// `myEval` does not match `eval`.
//
// A needle that starts with '.' is already anchored by its dot, so no left check is applied; a
// needle read as a callee is matched without a right check because dom.go appends the '(' itself.
// A '.' immediately before an unanchored needle is *allowed*: `frames[0].location` genuinely is a
// location source, and refusing it would drop a real case to avoid a rare one.
func domContainsToken(hay, needle string) bool {
	return domFindToken(hay, needle, 0) >= 0
}

// domFindToken returns the index of the first whole-token occurrence of needle at or after from, or
// -1. Separate from domContainsToken because sink matching needs the position to find the argument
// list that follows.
func domFindToken(hay, needle string, from int) int {
	if needle == "" || from > len(hay) {
		return -1
	}
	anchoredLeft := needle[0] == '.'
	for i := from; ; {
		rel := strings.Index(hay[i:], needle)
		if rel < 0 {
			return -1
		}
		at := i + rel
		i = at + 1
		if !anchoredLeft && at > 0 && domIdentByte(hay[at-1]) {
			continue
		}
		end := at + len(needle)
		if end < len(hay) && domIdentByte(hay[end]) {
			continue
		}
		return at
	}
}
