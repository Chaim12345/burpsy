package web

import (
	"encoding/json"
	"fmt"
	"html"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- CSRF PoC generation -----------------------------------------------------------------------
//
// Burp's Engagement tools turn a captured request into a ready-to-open HTML page that makes a
// browser replay it ("Generate CSRF PoC", generate-csrf-poc.html). The PoC is generated from the
// exchange's own bytes — method, scheme, host, path and body — so what the browser submits is what
// the client sent, not an approximation of it.
//
// The techniques are Burp's four, chosen manually or by "auto":
//
//   - form — hidden inputs, one per urlencoded body parameter. The browser re-encodes them, so the
//     submitted body is form-encoded exactly like the captured one.
//   - multipart — hidden inputs inside a form with enctype=multipart/form-data, one per parsed part.
//     The browser regenerates the boundary; the parts' names and values are what reproduce.
//   - plain — Burp's "plain text encoding" for bodies a form cannot encode field-by-field (JSON,
//     XML, anything raw): one hidden input inside a form with enctype=text/plain, the body split at
//     its first "=". The browser submits Content-Type: text/plain — the documented, deliberate
//     deviation, and the note says the application may reject it.
//   - xhr — a cross-domain XMLHttpRequest: the only technique that sends the exact Content-Type and
//     body verbatim, and the one that needs CORS, which the notes say out loud.
//
// auto follows the documented choice: urlencoded gives a form; multipart gives a multipart form;
// anything else with an "=" in the body gives the plain-text form (the exact-body technique that
// needs no CORS), and anything else gives the XHR. A manually selected technique that cannot
// reproduce the request still generates a best effort, with a warning — Burp's behaviour, and the
// honest one: a refusal teaches nothing about whether the attack works.
//
// Values are URL-decoded once (the form re-encodes them on submit) and HTML-escaped for attribute
// context, because a value containing `"` or `&` must arrive at the target as the operator's value
// rather than as markup.

type csrfParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type csrfView struct {
	Wired     bool        `json:"wired"`
	Technique string      `json:"technique"`
	Method    string      `json:"method"`
	Action    string      `json:"action"`
	Params    []csrfParam `json:"params"`
	HTML      string      `json:"html"`
	Notes     []string    `json:"notes"`
	// TestURL serves the generated HTML once, from the PoC host on its own
	// port — never from this console's origin (see poc_host.go for why that
	// property is the point). Empty unless the request asked for one.
	TestURL string `json:"test_url,omitempty"`
}

// handleCSRF answers GET /api/exchange/{id}/csrf with the generated PoC.
//
// Query parameters, all optional:
//
//	technique=auto|form|multipart|plain|xhr   (default auto)
//	auto_submit=true|false                   (default true — the script that
//	                                          fires the request on load)
//	test_url=true                            (also mint a one-shot PoC URL)
//
// Every unknown value is a 400 naming the parameter and its accepted values:
// a technique parameter that silently fell back to auto would generate a PoC
// the operator believes they configured and did not.
func (s *Server) handleCSRF(w http.ResponseWriter, r *http.Request, id core.ExchangeID) {
	technique := strings.TrimSpace(r.URL.Query().Get("technique"))
	switch technique {
	case "":
		technique = "auto"
	case "auto", "form", "multipart", "plain", "xhr":
	default:
		http.Error(w, `unknown technique `+strconv.Quote(technique)+`; the accepted values are auto, form, multipart, plain, xhr`, http.StatusBadRequest)
		return
	}
	autoSubmit := true
	if raw := r.URL.Query().Get("auto_submit"); raw != "" && raw != "true" && raw != "false" {
		http.Error(w, "auto_submit must be true or false, not "+strconv.Quote(raw), http.StatusBadRequest)
		return
	} else if raw == "false" {
		autoSubmit = false
	}
	wantTestURL := r.URL.Query().Get("test_url") == "true"
	if raw := r.URL.Query().Get("test_url"); raw != "" && !wantTestURL {
		http.Error(w, "test_url must be true, not "+strconv.Quote(raw), http.StatusBadRequest)
		return
	}

	ex, err := s.store.GetExchange(id)
	if err != nil {
		http.Error(w, "Exchange not found", http.StatusNotFound)
		return
	}
	msg, err := s.message(uint64(core.MsgOrZero(ex.Request)))
	if err != nil {
		http.Error(w, "Request bytes unavailable", http.StatusNotFound)
		return
	}
	raw := msg.Raw()

	lineEnd := strings.Index(string(raw), "\r\n")
	if lineEnd < 0 {
		http.Error(w, "Request has no readable request line", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(string(raw[:lineEnd]), " ", 3)
	if len(parts) < 2 {
		http.Error(w, "Request has no readable request line", http.StatusBadRequest)
		return
	}
	method := parts[0]

	scheme := "http"
	if ex.TLS {
		scheme = "https"
	}
	hostPort := ex.Host
	if (scheme == "https" && ex.Port != 443) || (scheme == "http" && ex.Port != 80) {
		hostPort = fmt.Sprintf("%s:%d", ex.Host, ex.Port)
	}
	action := scheme + "://" + hostPort + ex.Path

	headerEnd := strings.Index(string(raw), "\r\n\r\n")
	headers := ""
	body := ""
	if headerEnd >= 0 {
		headers = string(raw[:headerEnd])
		body = string(raw[headerEnd+4:])
	}
	var contentType string
	for _, line := range strings.Split(headers, "\r\n") {
		if len(line) > len("content-type:") && strings.EqualFold(line[:len("content-type:")], "content-type:") {
			contentType = strings.TrimSpace(line[len("content-type:"):])
		}
	}

	// Auto is Burp's documented preference order: the technique that needs
	// nothing beyond HTML forms first, XHR — the one that needs CORS — last.
	if technique == "auto" {
		technique = autoCSRFTechnique(contentType, body)
	}

	params := []csrfParam{}
	notes := []string{}
	var csrfHTML string

	switch technique {
	case "form":
		if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
			for _, pair := range strings.Split(body, "&") {
				if pair == "" {
					continue
				}
				name, value, _ := strings.Cut(pair, "=")
				params = append(params, csrfParam{Name: decodeFormComponent(name), Value: decodeFormComponent(value)})
			}
		} else if strings.TrimSpace(body) != "" {
			// Best effort with the warning, per the docs: "If you manually
			// select a CSRF technique that cannot be used to produce the
			// required request, Burp generates a best effort at a PoC and
			// displays a warning."
			notes = append(notes, "the form technique replays application/x-www-form-urlencoded bodies; this request's body ("+contentType+") was not one, so no body parameters were embedded — a dropped multipart boundary or a raw blob is not a proof")
		} else {
			notes = append(notes, "the request carried no form body; the PoC replays through the query string in the action")
		}
		csrfHTML = buildCSRFFormHTML(method, action, "", params, autoSubmit)

	case "multipart":
		mpParams, mpNotes := multipartParams(contentType, body)
		params, notes = mpParams, mpNotes
		csrfHTML = buildCSRFFormHTML(method, action, "multipart/form-data", params, autoSubmit)

	case "plain":
		eq := strings.Index(body, "=")
		if eq < 0 {
			notes = append(notes, "the plain-text technique needs an equals character in the body to reproduce it; this body has none, so the form cannot send it exactly — consider the cross-domain XHR technique")
			csrfHTML = buildCSRFFormHTML(method, action, "text/plain", nil, autoSubmit)
			break
		}
		// The browser's text/plain submission sends name + "=" + value and
		// appends a trailing CRLF after every entry, so the captured body
		// reproduces exactly when it already ends with that CRLF: it is cut
		// from the value and the browser puts it back.
		name, value := body[:eq], body[eq+1:]
		exact := strings.HasSuffix(value, "\r\n")
		if exact {
			value = strings.TrimSuffix(value, "\r\n")
		} else {
			notes = append(notes, "the browser's text/plain submission appends a trailing carriage return and line feed, so the body it sends is the captured body plus those two bytes")
		}
		params = append(params, csrfParam{Name: name, Value: value})
		if ct := contentType; ct != "" {
			notes = append(notes, "the browser submits this form as Content-Type: text/plain, not the captured "+ct+"; an application that rejects unexpected content types may refuse the request, and such CSRF-like conditions might not be practically exploitable")
		} else {
			notes = append(notes, "the browser submits this form as Content-Type: text/plain, not the captured request's content type; an application that rejects unexpected content types may refuse the request")
		}
		csrfHTML = buildCSRFFormHTML(method, action, "text/plain", params, autoSubmit)

	case "xhr":
		notes = append(notes, xhrNotes(contentType)...)
		csrfHTML = buildCSRFXHRHTML(method, action, headers, body, autoSubmit)
	}

	view := csrfView{
		Wired:     true,
		Technique: technique,
		Method:    method,
		Action:    action,
		Params:    params,
		HTML:      csrfHTML,
		Notes:     notes,
	}
	if wantTestURL {
		testURL, err := s.mintPocURL(csrfHTML)
		if err != nil {
			http.Error(w, "Minting a test URL failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		view.TestURL = testURL
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(view)
}

// autoCSRFTechnique is Burp's "Auto": the most appropriate technique capable
// of generating the required request, preferring the ones a plain HTML form
// can carry and reaching for the cross-domain XHR — the technique that needs
// CORS — only when nothing else can reproduce the body.
func autoCSRFTechnique(contentType, body string) string {
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "multipart/form-data"):
		return "multipart"
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		return "form"
	case strings.TrimSpace(body) == "":
		// No body at all: a form replays through the action's query string,
		// and Burp's default technique for a bodyless request is the form.
		return "form"
	case strings.Contains(body, "="):
		// JSON, XML or raw with an equals somewhere: the plain-text form
		// reproduces the exact body without needing CORS.
		return "plain"
	default:
		return "xhr"
	}
}

// multipartParams parses a captured multipart/form-data body into the parts
// a form can re-send: each field's name and value. The browser regenerates
// the boundary when the PoC's form submits, so the parts are the payload that
// matters and the framing is the browser's to make.
func multipartParams(contentType, body string) ([]csrfParam, []string) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return []csrfParam{}, []string{
			"the multipart technique needs a parsable multipart/form-data body with a boundary; this request's content type (" + contentType + ") did not carry one, so no parts were embedded",
		}
	}
	reader := multipart.NewReader(strings.NewReader(body), params["boundary"])
	form, err := reader.ReadForm(1 << 20)
	if err != nil {
		return []csrfParam{}, []string{
			"the captured multipart body could not be parsed (" + err.Error() + "); no parts were embedded, because a half-parsed body is not a proof",
		}
	}
	out := make([]csrfParam, 0, len(form.Value))
	for name, values := range form.Value {
		for _, value := range values {
			out = append(out, csrfParam{Name: name, Value: value})
		}
	}
	if len(out) == 0 {
		return out, []string{"the multipart body parsed to no form fields; file parts cannot be replayed by a generated form"}
	}
	return out, []string{"the browser regenerates the multipart boundary when the form submits, so the framing differs from the captured body; the parts' names and values are reproduced"}
}

// corsSimpleContentTypes are the Content-Type values that keep a cross-domain
// XHR a "simple request": no preflight, which the docs call out as the thing
// that "can break the attack".
var corsSimpleContentTypes = map[string]bool{
	"application/x-www-form-urlencoded": true,
	"multipart/form-data":               true,
	"text/plain":                        true,
}

// xhrNotes are the warnings the docs promise the generator displays for the
// cross-domain XHR technique: the CORS dependency, the preflight risk of a
// non-standard Content-Type, and what the technique cannot deliver.
func xhrNotes(contentType string) []string {
	notes := []string{
		"cross-domain XHR requires CORS: the target must allow this origin and credentials, or the browser blocks the request and the response",
	}
	essence := contentType
	if i := strings.IndexByte(essence, ';'); i >= 0 {
		essence = strings.TrimSpace(essence[:i])
	}
	if essence != "" && !corsSimpleContentTypes[strings.ToLower(essence)] {
		notes = append(notes, "the captured Content-Type ("+essence+") is not one a plain HTML form can carry, so the browser sends a CORS preflight first; the attack fails unless the target answers it permissively")
	}
	notes = append(notes,
		"the script sets withCredentials, so the victim's cookies ride the request; the headers a browser forbids scripts from setting (Host, Cookie, Content-Length and kin) are the browser's to send",
		"the application's response is not processed by the browser, so this technique cannot deliver reflected cross-site scripting",
	)
	return notes
}

func decodeFormComponent(raw string) string {
	if decoded, err := url.QueryUnescape(raw); err == nil {
		return decoded
	}
	// A value that does not decode is submitted verbatim rather than dropped: mangling it would put
	// bytes on the wire the operator never captured.
	return raw
}

// buildCSRFFormHTML renders the form techniques: hidden inputs inside a form
// whose enctype is the technique's encoding ("" is the default
// application/x-www-form-urlencoded). autoSubmit adds the script that fires
// the form on load, and history.pushState keeps the PoC's own URL out of the
// victim's address bar — the request must look like it came from nowhere.
func buildCSRFFormHTML(method, action, enctype string, params []csrfParam, autoSubmit bool) string {
	var b strings.Builder
	b.WriteString("<html>\n<!-- CSRF PoC - generated by burpsy -->\n<body>\n")
	enctypeAttr := ""
	if enctype != "" {
		enctypeAttr = fmt.Sprintf(" enctype=%q", html.EscapeString(enctype))
	}
	fmt.Fprintf(&b, "  <form action=\"%s\" method=\"%s\"%s>\n", html.EscapeString(action), html.EscapeString(method), enctypeAttr)
	for _, p := range params {
		fmt.Fprintf(&b, "    <input type=\"hidden\" name=\"%s\" value=\"%s\" />\n", html.EscapeString(p.Name), html.EscapeString(p.Value))
	}
	b.WriteString("    <input type=\"submit\" value=\"Submit request\" />\n")
	b.WriteString("  </form>\n")
	if autoSubmit {
		b.WriteString("  <script>\n")
		b.WriteString("    history.pushState('', '', '/');\n")
		b.WriteString("    document.forms[0].submit();\n")
		b.WriteString("  </script>\n")
	}
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

// browserForbiddenXHRHeaders are the headers the fetch specification forbids
// scripts from setting. Setting them would be silently ignored by the
// browser, which is worse than omitting them: a PoC that appears to set
// Cookie is a PoC that lies about what the victim's browser will send.
var browserForbiddenXHRHeaders = map[string]bool{
	"accept-charset": true, "accept-encoding": true, "access-control-request-headers": true,
	"access-control-request-method": true, "connection": true, "content-length": true,
	"cookie": true, "cookie2": true, "date": true, "dnt": true, "expect": true, "host": true,
	"keep-alive": true, "origin": true, "referer": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true, "via": true,
}

// buildCSRFXHRHTML renders the cross-domain XHR technique: the only one that
// sends the exact Content-Type and body, and the one that depends on CORS.
// Headers the browser owns are omitted rather than set-and-ignored.
func buildCSRFXHRHTML(method, action, headers, body string, autoSubmit bool) string {
	var b strings.Builder
	b.WriteString("<html>\n<!-- CSRF PoC - generated by burpsy -->\n<body>\n  <script>\n")
	b.WriteString("    function send() {\n")
	b.WriteString("      var xhr = new XMLHttpRequest();\n")
	fmt.Fprintf(&b, "      xhr.open(%s, %s, true);\n", jsString(method), jsString(action))
	b.WriteString("      xhr.withCredentials = true;\n")
	for _, line := range strings.Split(headers, "\r\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if browserForbiddenXHRHeaders[strings.ToLower(strings.TrimSpace(name))] ||
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(name)), "proxy-") ||
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(name)), "sec-") {
			continue
		}
		fmt.Fprintf(&b, "      xhr.setRequestHeader(%s, %s);\n", jsString(strings.TrimSpace(name)), jsString(strings.TrimSpace(value)))
	}
	fmt.Fprintf(&b, "      xhr.send(%s);\n", jsString(body))
	b.WriteString("    }\n")
	if autoSubmit {
		b.WriteString("    history.pushState('', '', '/');\n")
		b.WriteString("    send();\n")
	}
	b.WriteString("  </script>\n")
	if !autoSubmit {
		b.WriteString("  <button onclick=\"send()\">Send request</button>\n")
	}
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

// jsString renders a Go string as a JavaScript single-quoted string literal.
// "<" becomes the \u003c escape: a literal "</script>" inside a JS string would
// close the script element and turn the rest of the PoC into markup, which is
// exactly how a PoC about a captured body stops being the PoC it claims.
func jsString(v string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString("\\\\")
		case '\'':
			b.WriteString("\\'")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '<':
			b.WriteString("\\u003c")
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}
