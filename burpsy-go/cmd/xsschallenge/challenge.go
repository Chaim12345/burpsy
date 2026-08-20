package main

// The challenge target: 20 genuinely exploitable XSS endpoints and 6 that only look like it.
//
// # Why this exists
//
// internal/vulnapp is a COOPERATIVE target. Every endpoint there was written next to the check it
// demonstrates, and it declares the row it expects. That proves a check can fire; it cannot prove a
// check finds anything it was not shown. Those are different claims and the project only had
// evidence for the first.
//
// This file is the adversarial counterpart. It declares no rows, is not in the manifest, and is not
// part of the coverage number. The scanner meets it with no knowledge of it whatsoever: it is handed
// one captured request per endpoint carrying a benign value, exactly as a proxy would, and has to
// work the rest out.
//
// # How the contexts were chosen
//
// From the public XSS context taxonomy - HTML body, quoted and unquoted attributes, JS string
// literals, comments, RCDATA elements, URL attributes - plus the filter classes real applications
// ship: blocklists that strip a tag name, blocklists that strip event handlers, single-pass
// case-sensitive filters, length caps, and a decode performed after validation. Deliberately NOT
// from reading internal/scanner's XSS checks: a challenge written against the detector's
// implementation measures nothing except itself.
//
// # The safe six
//
// Six endpoints reflect input and are not exploitable. They are the false-positive half of the
// experiment, and they matter as much as the vulnerable twenty: a scanner that reports everything
// finds everything, and is worthless. Each is safe for a different reason - full escaping, an
// attribute with every metacharacter escaped, JSON serialisation into a script, textContent, a
// non-HTML content type with nosniff, and an allowlist that keeps only alphanumerics.

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// pwn is the marker every exploit sets. Phase 1 loads each endpoint with its exploit in a real
// browser and asks whether this is set: that, and nothing else, is what makes a case "vulnerable".
// A case whose exploit does not fire is a broken fixture, and the run says so rather than counting
// it as a scanner miss.
const pwn = "window.__pwned=1"

// xcase is one endpoint. exploit is a payload PROVEN to execute in phase 1; vulnerable records the
// intent, and phase 1 either confirms it or fails the run.
type xcase struct {
	name       string
	path       string
	param      string
	exploit    string
	vulnerable bool
	context    string
	// stored means the payload is planted at path and fires at viewPath.
	stored   bool
	viewPath string
	// fragment means the exploit belongs after '#', so it never reaches the server.
	fragment bool
	// header and cookie mean the reflection source is a request header or cookie, not a parameter.
	header string
	cookie string
	// clickSelector, when set, is clicked after load: some sinks legitimately need an interaction,
	// and a virtual display makes a real click possible rather than simulated.
	clickSelector string
}

func cases() []xcase {
	return []xcase{
		// ---- HTML body ----
		{
			name: "raw-body", path: "/x/raw", param: "q",
			exploit: "<script>" + pwn + "</script>", vulnerable: true,
			context: "raw reflection into the HTML body, no filtering at all - the baseline",
		},
		{
			name: "strip-script-word", path: "/x/stripword", param: "q",
			exploit: `<img src=x onerror=` + pwn + `>`, vulnerable: true,
			context: "blocklist deletes every occurrence of 'script', so the tag is unusable but " +
				"an event handler on another tag is untouched",
		},
		{
			name: "strip-lowercase-tag", path: "/x/stripcase", param: "q",
			exploit: "<ScRiPt>" + pwn + "</ScRiPt>", vulnerable: true,
			context: "case-SENSITIVE blocklist strips '<script' only in lower case",
		},
		{
			name: "strip-event-handlers", path: "/x/stripevents", param: "q",
			exploit: `<details open ontoggle=` + pwn + `>`, vulnerable: true,
			context: "blocklist strips onerror and onload by name, leaving every other handler",
		},
		{
			name: "length-capped", path: "/x/lencap", param: "q",
			exploit: `<svg onload=` + pwn + `>`, vulnerable: true,
			context: "reflection truncated to 30 characters, so only a short payload survives",
		},
		{
			name: "decode-after-filter", path: "/x/doubledecode", param: "q",
			exploit: `%3Cscr%69pt%3E` + pwn + `%3C/scr%69pt%3E`, vulnerable: true,
			context: "the value is percent-decoded a second time AFTER the tag filter has run, so an " +
				"encoded payload passes the filter and is decoded into markup",
		},
		{
			name: "json-typed-html", path: "/x/jsonhtml", param: "q",
			exploit: "<script>" + pwn + "</script>", vulnerable: true,
			context: "a JSON document served as text/html, so the browser parses the reflected value " +
				"as markup",
		},
		{
			name: "svg-body", path: "/x/svg", param: "q",
			exploit: "<script>" + pwn + "</script>", vulnerable: true,
			context: "reflection inside an inline <svg>, where a script element still executes",
		},

		// ---- attributes ----
		{
			name: "attr-double-quoted", path: "/x/attrdouble", param: "q",
			exploit: `" autofocus onfocus="` + pwn, vulnerable: true,
			context: `inside <input value="...">; angle brackets escaped, the double quote is not, so ` +
				`the payload cannot open a tag and must add attributes to this one`,
		},
		{
			name: "attr-single-quoted", path: "/x/attrsingle", param: "q",
			exploit: `' autofocus onfocus='` + pwn, vulnerable: true,
			context: `inside <input value='...'>; angle brackets AND double quotes escaped, the single ` +
				`quote is not - the classic half-done escaping`,
		},
		{
			name: "attr-unquoted", path: "/x/attrunquoted", param: "q",
			// Two real constraints of this context, both of which the payload has to respect. An
			// unquoted attribute value may not contain '=', so the handler sets the marker without an
			// assignment operator. And whitespace after '=' is skipped by the parser, so a payload
			// starting with a space would have `autofocus` consumed as value's value rather than
			// becoming an attribute of its own - hence the leading token.
			exploit: `x autofocus onfocus=Object.assign(window,{__pwned:1})`, vulnerable: true,
			context: "inside an UNQUOTED attribute value; both quote characters and angle brackets " +
				"are escaped, so the payload needs neither - a space is enough to add attributes, " +
				"though the handler itself cannot contain '='",
		},
		{
			name: "attr-url-javascript", path: "/x/attrurl", param: "q",
			exploit: `javascript:` + pwn, vulnerable: true,
			clickSelector: "#go",
			context: `into <a href="...">; quotes and angle brackets escaped, but the scheme is never ` +
				`checked. Exploiting it needs a click, which is true of the real defect too, so phase ` +
				`1 performs a real one on the virtual display`,
		},
		{
			name: "attr-srcdoc", path: "/x/srcdoc", param: "q",
			exploit: `&lt;script&gt;parent.__pwned=1&lt;/script&gt;`, vulnerable: true,
			context: `into <iframe srcdoc="...">, which is an attribute whose CONTENT is parsed as ` +
				`HTML - so an HTML-escaped payload is unescaped once by the attribute parser and ` +
				`becomes markup, a double-context flaw`,
		},

		// ---- script and RCDATA contexts ----
		{
			name: "js-single-quoted-string", path: "/x/jsstring", param: "q",
			exploit: `';` + pwn + `;//`, vulnerable: true,
			context: "inside a single-quoted JS string literal; angle brackets escaped so no tag can " +
				"be injected, but the quote closes the literal",
		},
		{
			name: "js-script-close", path: "/x/jsclose", param: "q",
			exploit: `</script><script>` + pwn + `</script>`, vulnerable: true,
			context: "inside a double-quoted JS string literal with quotes escaped - but the parser " +
				"leaves the script element on </script> regardless of JS syntax",
		},
		{
			name: "html-comment", path: "/x/comment", param: "q",
			exploit: `--><script>` + pwn + `</script><!--`, vulnerable: true,
			context: "inside an HTML comment; nothing escaped, so the comment can be closed",
		},
		{
			name: "textarea", path: "/x/textarea", param: "q",
			exploit: `</textarea><script>` + pwn + `</script>`, vulnerable: true,
			context: "inside <textarea>, an RCDATA element - safe until the closing tag is injected",
		},
		{
			name: "title", path: "/x/title", param: "q",
			exploit: `</title><script>` + pwn + `</script>`, vulnerable: true,
			context: "inside <title>, the other RCDATA element",
		},

		// ---- flows that are not a single request/response ----
		{
			name: "stored", path: "/x/stored/plant", param: "note",
			viewPath: "/x/stored/view", stored: true,
			exploit: "<script>" + pwn + "</script>", vulnerable: true,
			context: "planted by one request and rendered raw by a DIFFERENT page, so no response " +
				"the planting request sees contains the payload",
		},
		{
			name: "dom-hash", path: "/x/domhash", param: "",
			fragment: true,
			exploit:  `<img src=x onerror=` + pwn + `>`, vulnerable: true,
			context: "the page reads location.hash and assigns it to innerHTML, so the payload never " +
				"reaches the server at all",
		},
		{
			name: "header-user-agent", path: "/x/header", param: "",
			header:  "User-Agent",
			exploit: "<script>" + pwn + "</script>", vulnerable: true,
			context: "the User-Agent header is reflected into the body, so no parameter is involved",
		},
		{
			name: "cookie-pref", path: "/x/cookie", param: "",
			cookie:  "pref",
			exploit: "<script>" + pwn + "</script>", vulnerable: true,
			context: "a cookie value is reflected into the body",
		},

		// ---- reflection into an EXISTING inline handler ----
		//
		// The pair a confirmation that only checks "the canary is in an on* attribute" cannot tell
		// apart: both reflect into onclick, and only one escapes the JS literal it lands in.
		{
			name: "handler-literal-raw", path: "/x/handler", param: "q",
			// The call has to be closed as well as the literal: `track('';…)` puts a statement inside
			// an argument list and is a SyntaxError, so the handler never compiles and nothing runs.
			exploit: `');window.__pwned=1;//`, vulnerable: true, clickSelector: "#go",
			context: "reflected raw into a single-quoted JS string inside an existing onclick handler, " +
				"so closing the literal executes",
		},
		{
			name: "attr-url-img", path: "/x/imgsrc", param: "q",
			exploit: `javascript:window.__pwned=1`, vulnerable: false,
			context: "a javascript: value reflected into <img src>, which no current browser executes - " +
				"a URL-valued attribute is not the same thing as an executable one",
		},

		// ---- the safe set: reflected, not exploitable ----
		{
			name: "safe-handler-literal", path: "/s/handler", param: "q",
			exploit: `');window.__pwned=1;//`, vulnerable: false, clickSelector: "#go",
			context: "reflected into the same existing onclick handler, with the JS literal escaped and " +
				"then attribute-escaped - correct output, and the shape that exposes a confirmation " +
				"which only checks whether the canary is in a handler",
		},
		{
			name: "safe-attr-quote-escaped", path: "/s/attrquote", param: "q",
			exploit: `" autofocus onfocus="` + pwn, vulnerable: false,
			context: `inside <input value="..."> with ONLY the quote escaped - correct for a quoted ` +
				`attribute, since nothing can close the value, yet the raw marker bytes still appear ` +
				`in the response`,
		},
		{
			name: "safe-escaped-body", path: "/s/escaped", param: "q",
			exploit: "<script>" + pwn + "</script>", vulnerable: false,
			context: "reflected into the body with full HTML escaping",
		},
		{
			name: "safe-escaped-attr", path: "/s/attr", param: "q",
			exploit: `" autofocus onfocus="` + pwn, vulnerable: false,
			context: "reflected into a quoted attribute with every metacharacter escaped",
		},
		{
			name: "safe-json-in-script", path: "/s/jsjson", param: "q",
			exploit: `';` + pwn + `;//`, vulnerable: false,
			context: "reflected into a script as a JSON-serialised value, which escapes what matters",
		},
		{
			name: "safe-textcontent", path: "/s/textcontent", param: "",
			fragment: true,
			exploit:  `<img src=x onerror=` + pwn + `>`, vulnerable: false,
			context: "the page reads location.hash and assigns it to textContent",
		},
		{
			name: "safe-plaintext", path: "/s/plaintext", param: "q",
			exploit: "<script>" + pwn + "</script>", vulnerable: false,
			context: "reflected raw but served as text/plain with nosniff, so it is never parsed",
		},
		{
			name: "safe-allowlist", path: "/s/allowlist", param: "q",
			exploit: `" autofocus onfocus="` + pwn, vulnerable: false,
			context: "reflected after an allowlist keeps alphanumerics only",
		},
	}
}

// ---- the server ----

var (
	storedMu  sync.Mutex
	storedLog []string
)

var (
	reScriptWord  = regexp.MustCompile(`(?i)script`)
	reLowerScript = regexp.MustCompile(`<script`)
	reEventAttrs  = regexp.MustCompile(`(?i)on(error|load)`)
	reNonAlnum    = regexp.MustCompile(`[^A-Za-z0-9]+`)
)

// escAngle escapes only < and >, which is the most common incomplete escaping in the wild.
func escAngle(s string) string {
	return strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(s)
}

func escAngleAndDouble(s string) string {
	return strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func escAngleAndQuotes(s string) string {
	return strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}

func page(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>challenge</title></head>"+
		"<body>%s</body></html>", body)
}

func q(r *http.Request, name string) string { return r.URL.Query().Get(name) }

func challengeMux() *http.ServeMux {
	mux := http.NewServeMux()

	// ---- HTML body ----
	mux.HandleFunc("/x/raw", func(w http.ResponseWriter, r *http.Request) {
		page(w, "<p>you searched for "+q(r, "q")+"</p>")
	})
	mux.HandleFunc("/x/stripword", func(w http.ResponseWriter, r *http.Request) {
		page(w, "<p>hello "+reScriptWord.ReplaceAllString(q(r, "q"), "")+"</p>")
	})
	mux.HandleFunc("/x/stripcase", func(w http.ResponseWriter, r *http.Request) {
		page(w, "<p>hello "+reLowerScript.ReplaceAllString(q(r, "q"), "")+"</p>")
	})
	mux.HandleFunc("/x/stripevents", func(w http.ResponseWriter, r *http.Request) {
		page(w, "<p>hello "+reEventAttrs.ReplaceAllString(q(r, "q"), "")+"</p>")
	})
	mux.HandleFunc("/x/lencap", func(w http.ResponseWriter, r *http.Request) {
		v := q(r, "q")
		if len(v) > 30 {
			v = v[:30]
		}
		page(w, "<p>note: "+v+"</p>")
	})
	mux.HandleFunc("/x/doubledecode", func(w http.ResponseWriter, r *http.Request) {
		v := q(r, "q")
		// The filter runs first...
		v = reScriptWord.ReplaceAllString(v, "")
		// ...and the decode runs after it, which is the entire defect.
		if dec, err := url.QueryUnescape(v); err == nil {
			v = dec
		}
		page(w, "<p>ref: "+v+"</p>")
	})
	mux.HandleFunc("/x/jsonhtml", func(w http.ResponseWriter, r *http.Request) {
		// Deliberately the wrong content type for a JSON body.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `{"echo":%q}`, q(r, "q"))
	})
	mux.HandleFunc("/x/svg", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<svg width="200" height="40"><text x="0" y="20">`+q(r, "q")+`</text></svg>`)
	})

	// ---- attributes ----
	// These three use the textbook attribute-context payload: close the value, then add `autofocus`
	// and an `onfocus` handler. Nothing here uses src/onerror - an earlier version of this comment
	// described a design that was never written, and pointed away from the real mechanism when the
	// fixtures failed. Focus is delivered explicitly by phase 1 rather than left to window
	// activation, which is what actually varies between browser modes.
	mux.HandleFunc("/x/attrdouble", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<input value="`+escAngle(q(r, "q"))+`">`)
	})
	mux.HandleFunc("/x/attrsingle", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<input value='`+escAngleAndDouble(q(r, "q"))+`'>`)
	})
	mux.HandleFunc("/x/attrunquoted", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<input value=`+escAngleAndQuotes(q(r, "q"))+`>`)
	})
	mux.HandleFunc("/x/attrurl", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<a id="go" href="`+escAngleAndQuotes(q(r, "q"))+`">continue</a>`)
	})
	mux.HandleFunc("/x/srcdoc", func(w http.ResponseWriter, r *http.Request) {
		// The value is escaped for an attribute, which is correct for every attribute except this
		// one: srcdoc's content is parsed as HTML, so the escaping is undone before parsing.
		page(w, `<iframe width="10" height="10" srcdoc="`+escAngleAndQuotes(q(r, "q"))+`"></iframe>`)
	})

	// ---- script and RCDATA ----
	mux.HandleFunc("/x/jsstring", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<script>var query = '`+escAngle(q(r, "q"))+`'; void query;</script>`)
	})
	mux.HandleFunc("/x/jsclose", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<script>var query = "`+strings.ReplaceAll(q(r, "q"), `"`, `\"`)+`"; void query;</script>`)
	})
	mux.HandleFunc("/x/comment", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<!-- last query: `+q(r, "q")+` -->`)
	})
	mux.HandleFunc("/x/textarea", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<textarea rows="2">`+q(r, "q")+`</textarea>`)
	})
	mux.HandleFunc("/x/title", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><head><title>`+q(r, "q")+`</title></head><body>ok</body></html>`)
	})

	// ---- multi-step and non-parameter flows ----
	mux.HandleFunc("/x/stored/plant", func(w http.ResponseWriter, r *http.Request) {
		storedMu.Lock()
		storedLog = append(storedLog, q(r, "note"))
		if len(storedLog) > 40 {
			storedLog = storedLog[len(storedLog)-40:]
		}
		storedMu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "saved\n")
	})
	mux.HandleFunc("/x/stored/view", func(w http.ResponseWriter, r *http.Request) {
		storedMu.Lock()
		notes := strings.Join(storedLog, "<br>")
		storedMu.Unlock()
		page(w, "<div id=notes>"+notes+"</div>")
	})
	mux.HandleFunc("/x/domhash", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<div id="out"></div><script>
document.getElementById('out').innerHTML = decodeURIComponent(location.hash.slice(1));
</script>`)
	})
	mux.HandleFunc("/x/header", func(w http.ResponseWriter, r *http.Request) {
		page(w, "<p>your browser: "+r.Header.Get("User-Agent")+"</p>")
	})
	mux.HandleFunc("/x/cookie", func(w http.ResponseWriter, r *http.Request) {
		v := ""
		if c, err := r.Cookie("pref"); err == nil {
			v = c.Value
		}
		page(w, "<p>preference: "+v+"</p>")
	})

	// An existing inline handler holding a reflected value. The vulnerable one splices raw; the safe
	// one escapes for the JS literal AND then for the attribute, which is what correct output is here.
	mux.HandleFunc("/x/handler", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<button id="go" onclick="track('`+q(r, "q")+`')">go</button><script>function track(x){void x;}</script>`)
	})
	mux.HandleFunc("/s/handler", func(w http.ResponseWriter, r *http.Request) {
		v := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(q(r, "q"))
		page(w, `<button id="go" onclick="track('`+html.EscapeString(v)+`')">go</button><script>function track(x){void x;}</script>`)
	})
	// A javascript: value in <img src>. Reflected, and inert in every current browser.
	mux.HandleFunc("/x/imgsrc", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<img src="`+escAngleAndQuotes(q(r, "q"))+`" alt="avatar">`)
	})
	// Only the quote escaped, which is correct for a quoted attribute value.
	mux.HandleFunc("/s/attrquote", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<input value="`+strings.ReplaceAll(q(r, "q"), `"`, "&quot;")+`">`)
	})

	// ---- the safe six ----
	mux.HandleFunc("/s/escaped", func(w http.ResponseWriter, r *http.Request) {
		page(w, "<p>you searched for "+html.EscapeString(q(r, "q"))+"</p>")
	})
	mux.HandleFunc("/s/attr", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<input value="`+html.EscapeString(q(r, "q"))+`">`)
	})
	mux.HandleFunc("/s/jsjson", func(w http.ResponseWriter, r *http.Request) {
		b, err := json.Marshal(q(r, "q"))
		if err != nil {
			b = []byte(`""`)
		}
		page(w, `<script>var query = `+string(b)+`; void query;</script>`)
	})
	mux.HandleFunc("/s/textcontent", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<div id="out"></div><script>
document.getElementById('out').textContent = decodeURIComponent(location.hash.slice(1));
</script>`)
	})
	mux.HandleFunc("/s/plaintext", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, "you searched for "+q(r, "q"))
	})
	mux.HandleFunc("/s/allowlist", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<p class="`+reNonAlnum.ReplaceAllString(q(r, "q"), "")+`">filtered</p>`)
	})

	return mux
}
